-module(emqx_data_converter).

%% API exports
-export([main/1]).

-define(CLI_OPTS,
        [{output_dir, $o, "output-dir", {string, undefined},
          "A directory path where output EMQX 5.1 backup tar.gz file will be written. "
          "If omitted, the file is written to CWD."},
         {user_id_type, $u, "user-id-type", {binary, undefined},
          "User type (clientid or username) of built-in DB (Mnesia) authentication credentials to migrate. "
          "EMQX 4.4 supports both clientid and username credentials at the same time, while EMQX 5.1 uses "
          "one type at a time. If this option is not provided, the user type that has more credentials in "
          "the input file will be chosen."},
         {jwt_type, $j, "jwt-type", {binary, undefined},
          "JWT authentication type to migrate. Possible values: hmac-based, public-key, jwks. EMQX 5.1 supports "
          "only one of the aforementioned types at a time. If this option is omitted, JWT authentication is migrated "
          "according to the following (descending) precedence: 1. jwks, 2. public-key, 3. hmac-based."},
         {edition, $e, "emqx-edition", {string, "ee"},
          "EMQX edition of the both input and output backup files. Possible values: ee, ce. "
          "Please note that EMQX 5.1 doesn't allow to import ee backup file to ce cluster."},
         {input_file, undefined, undefined, string, "Input EMQX 4.4 backup JSON file path."}]).

-type user_group() :: binary().
-type user_id() :: binary().

-record(user_info,
        {
         user_id :: {user_group(), user_id()},
         password_hash :: binary(),
         salt :: binary(),
         is_superuser :: boolean()
        }).

-define(ACL_TABLE_ALL, 0).
-define(ACL_TABLE_USERNAME, 1).
-define(ACL_TABLE_CLIENTID, 2).

-define(ACL_FILE_COMMENTS,
        "%%--------------------------------------------------------------------\n"
        "%% -type(ipaddr() :: {ipaddr, string()}).\n"
        "%%\n"
        "%% -type(ipaddrs() :: {ipaddrs, [string()]}).\n"
        "%%\n"
        "%% -type(username() :: {user | username, string()} | {user | username, {re, regex()}}).\n"
        "%%\n"
        "%% -type(clientid() :: {client | clientid, string()} | {client | clientid, {re, regex()}}).\n"
        "%%\n"
        "%% -type(who() :: ipaddr() | ipaddrs() | username() | clientid() |\n"
        "%%                {'and', [ipaddr() | ipaddrs() | username() | clientid()]} |\n"
        "%%                {'or',  [ipaddr() | ipaddrs() | username() | clientid()]} |\n"
        "%%                all).\n%%\n%% -type(action() :: subscribe | publish | all).\n"
        "%%\n"
        "%% -type(topic_filters() :: string()).\n"
        "%%\n"
        "%% -type(topics() :: [topic_filters() | {eq, topic_filters()}]).\n"
        "%%\n"
        "%% -type(permission() :: allow | deny).\n"
        "%%\n"
        "%% -type(rule() :: {permission(), who(), action(), topics()} | {permission(), all}).\n"
        "%%--------------------------------------------------------------------\n\n"
       ).

-type action() :: subscribe | publish | all.
-type permission() :: allow | deny.
-type topic() :: binary().

-type rule() :: {permission(), action(), topic()}.
-type rules() :: [rule()].

-record(emqx_acl, {
    who :: ?ACL_TABLE_ALL | {?ACL_TABLE_USERNAME, binary()} | {?ACL_TABLE_CLIENTID, binary()},
    rules :: rules()
}).

-define(tar(_FileName_), _FileName_ ++ ?TAR_SUFFIX).
-define(TAR_SUFFIX, ".tar.gz").

-define(fmt_tar_err(_Expr_),
    fun() ->
        case _Expr_ of
            {error, _Reason_} -> {error, erl_tar:format_error(_Reason_)};
            _Other_ -> _Other_
        end
    end()
).

-define(META_FILENAME, "META.hocon").
-define(CLUSTER_HOCON_FILENAME, "cluster.hocon").
-define(BACKUP_MNESIA_DIR, "mnesia").
-define(AUTHN_CHAIN_5_1, 'mqtt:global').
-define(VERSION_5_1, "5.1.1").

-define(PLACEHOLDERS,
        [{<<"${username}">>, <<"%u">>},
         {<<"${clientid}">>, <<"%c">>},
         {<<"${cert_common_name}">>, <<"%C">>},
         {<<"${cert_subject}">>, <<"%d">>},
         {<<"${peerhost}">>, <<"%a">>},
         {<<"${password}">>, <<"%P">>}
        ]).

-compile(export_all).

%%====================================================================
%% API functions
%%====================================================================

%% escript Entry point

main([]) ->
    show_usage_exit(1);
main([H]) when H =:= "-h"; H =:= "--help" ->
    show_usage_exit(0);
main([V]) when V =:= "-v"; V =:= "--version" ->
    ok = application:load(emqx_data_converter),
    {_, _, Ver} = lists:keyfind(emqx_data_converter, 1, application:loaded_applications()),
    io:format("~s~n", [Ver]),
    halt(0);
main(Args) ->
    {ok, {Opts, _}} = getopt:parse(?CLI_OPTS, Args),
    validate_input_file(proplists:get_value(input_file, Opts)),
    validate_jwt_type(proplists:get_value(jwt_type, Opts)),
    validate_user_id_type(proplists:get_value(user_id_type, Opts)),
    validate_edition(proplists:get_value(edition, Opts)),
    application:ensure_all_started(emqx_data_converter),
    try
        main1(Opts)
    after
        file:del_dir_r("Mnesia." ++ atom_to_list(node()))
    end.

%%====================================================================
%% Internal functions
%%====================================================================

validate_input_file(undefined) ->
    io:format("[ERROR] Missing required argument: <input_file>~n", []),
    show_usage_exit(1);
validate_input_file(_) -> ok.

validate_user_id_type(T) when T =:= <<"clientid">>;
                              T =:= <<"username">>;
                              T =:= undefined ->
    ok;
validate_user_id_type(T) ->
    io:format("[ERROR] Invalid user-id-type: ~s~n", [T]),
    show_usage_exit(1).

validate_jwt_type(T) when T =:= <<"public-key">>;
                          T =:= <<"hmac-based">>;
                          T =:= <<"jwks">>;
                          T =:= undefined ->
    ok;
validate_jwt_type(T) ->
    io:format("[ERROR] Invalid jwt-type: ~s~n", [T]),
    show_usage_exit(1).

validate_edition(E) when E =:= "ee"; E =:= "ce" ->
    ok;
validate_edition(E) ->
    io:format("[ERROR] Invalid EMQX edition: ~s~n", [E]),
    show_usage_exit(1).

show_usage_exit(Reason) ->
    getopt:usage(?CLI_OPTS, escript:script_name(), standard_io),
    halt(Reason).

main1(Opts) ->
    OutputDir = case proplists:get_value(output_dir, Opts) of
                    undefined ->
                        {ok, CWD} = file:get_cwd(),
                        CWD;
                    ODir -> ODir
                end,
    UserIdType = proplists:get_value(user_id_type, Opts),
    JwtType = proplists:get_value(jwt_type, Opts),
    {ok, InputBin} = file:read_file(proplists:get_value(input_file, Opts)),
    InputMap = jsone:decode(InputBin),
    ok = setup_mnesia(),
    {ok, UserIdType1} = convert_auth_mnesia(InputMap, UserIdType),
    ok = convert_acl_mnesia(InputMap),
    OutRawConf = convert_auth_modules(InputMap, #{output_dir => OutputDir,
                                                  user_id_type => UserIdType1,
                                                  jwt_type => JwtType}),

    {BackupName, TarDescriptor} = prepare_new_backup(OutputDir),
    Edition = proplists:get_value(edition, Opts),
    {ok, BackupTarName} = export(OutRawConf, BackupName, TarDescriptor, Edition),
    file:del_dir_r(BackupName),
    io:format("[INFO] Converted to EMQX 5.1 backup file: ~s~n", [BackupTarName]).

setup_mnesia() ->
    mnesia:delete_schema([node()]),
    ok = mnesia:create_schema([node()]),
    ok = mnesia:start(),
    maps:foreach(fun create_table/2, tabs_spec()).

tabs_spec() ->
    #{emqx_authn_mnesia =>
          [{type, ordered_set},
           {record_name, user_info},
           {attributes, record_info(fields, user_info)}
          ],
     emqx_acl =>
          [{type, ordered_set},
           {record_name, emqx_acl},
           {attributes, record_info(fields, emqx_acl)}
          ]
     }.

create_table(Name, Opts0) ->
    Opts = [{disc_copies, [node()]} | Opts0],
    {atomic, ok} = mnesia:create_table(Name, Opts),
    ok = mnesia:wait_for_tables([Name], infinity).

prepare_new_backup(OutputDir) ->
    Ts = erlang:system_time(millisecond),
    {{Y, M, D}, {HH, MM, SS}} = local_datetime(Ts),
    BackupBaseName = str(
        io_lib:format(
            "emqx-export-~0p-~2..0b-~2..0b-~2..0b-~2..0b-~2..0b.~3..0b",
            [Y, M, D, HH, MM, SS, Ts rem 1000]
        )
    ),
    BackupName = filename:join(OutputDir, BackupBaseName),
    BackupTarName = ?tar(BackupName),
    {ok, TarDescriptor} = ?fmt_tar_err(erl_tar:open(BackupTarName, [write, compressed])),
    {BackupName, TarDescriptor}.

export(OutRawConf, BackupName, TarDescriptor, Edition) ->
    BackupBaseName = filename:basename(BackupName),
    BackupTarName = ?tar(BackupName),
    Meta = #{
             version => ?VERSION_5_1,
             edition => Edition
            },
    MetaBin = bin(hocon_pp:do(Meta, #{})),
    MetaFileName = filename:join(BackupBaseName, ?META_FILENAME),
    ok = ?fmt_tar_err(erl_tar:add(TarDescriptor, MetaBin, MetaFileName, [])),
    ok = export_mnesia_tabs(TarDescriptor, BackupName, BackupBaseName),
    RawConfBin = bin(hocon_pp:do(OutRawConf, #{})),
    ConfNameInArchive = filename:join(BackupBaseName, ?CLUSTER_HOCON_FILENAME),
    ok = ?fmt_tar_err(erl_tar:add(TarDescriptor, RawConfBin, ConfNameInArchive, [])),
    ok = ?fmt_tar_err(erl_tar:close(TarDescriptor)),
    {ok, BackupTarName}.

export_mnesia_tabs(TarDescriptor, BackupName, BackupBaseName) ->
    lists:foreach(
        fun(Tab) -> export_mnesia_tab(TarDescriptor, Tab, BackupName, BackupBaseName) end,
        maps:keys(tabs_spec())
    ).

export_mnesia_tab(TarDescriptor, TabName, BackupName, BackupBaseName) ->
    {ok, MnesiaBackupName} = do_export_mnesia_tab(TabName, BackupName),
    NameInArchive = mnesia_backup_name(BackupBaseName, TabName),
    ok = ?fmt_tar_err(erl_tar:add(TarDescriptor, MnesiaBackupName, NameInArchive, [])),
    _ = file:delete(MnesiaBackupName),
    ok.

do_export_mnesia_tab(TabName, BackupName) ->
    Node = node(),
    try
        {ok, TabName, [Node]} = mnesia:activate_checkpoint(
            [{name, TabName}, {min, [TabName]}, {allow_remote, false}]
        ),
        MnesiaBackupName = mnesia_backup_name(BackupName, TabName),
        ok = filelib:ensure_dir(MnesiaBackupName),
        ok = mnesia:backup_checkpoint(TabName, MnesiaBackupName),
        {ok, MnesiaBackupName}
    after
        mnesia:deactivate_checkpoint(TabName)
    end.

mnesia_backup_name(Path, TabName) ->
    filename:join([Path, ?BACKUP_MNESIA_DIR, atom_to_list(TabName)]).

convert_auth_mnesia(#{<<"auth_mnesia">> := AuthMnesiaData}, UserIdType) ->
    UserIdType1 = user_type(AuthMnesiaData, UserIdType),
    lists:foreach(
      fun(#{<<"login">> := L, <<"type">> := T, <<"password">> := P}) when T =:= UserIdType1 ->
              <<Salt:32, PHash/binary>> = base64:decode(P),
              ok = mnesia:dirty_write(
                     emqx_authn_mnesia,
                     #user_info{user_id = {?AUTHN_CHAIN_5_1, L},
                                password_hash = PHash,
                                salt = <<Salt:32>>,
                                is_superuser = false}
                    );
         (_) ->
              ok
      end,
      AuthMnesiaData
     ),
    {ok, UserIdType1};
convert_auth_mnesia(_InputMap, UserIdType) ->
    {ok, UserIdType}.

user_type(AuthMnesiaData, undefined) ->
    {UserCount, ClientCount} =
        lists:foldl(fun(#{<<"type">> := <<"username">>}, {UAcc, CAcc}) ->
                            {UAcc+1, CAcc};
                       (#{<<"type">> := <<"clientid">>}, {UAcc, CAcc}) ->
                            {UAcc, CAcc+1}
                    end,
                    {0, 0},
                    AuthMnesiaData),
    case {UserCount, ClientCount} of
        {0, 0} -> undefined;
        {C, C} ->
            io:format("[INFO] Input file has equal numbers of username and clientid internal DB credentials, "
                      "choosing username for migration. If you need to migrate clientid instead, please re-run the converter with: "
                      "--user-id-type clientid~n~n", []),
            <<"username">>;
        {U, C} ->
            {Chosen, Discarded} = case U > C of
                                      true -> {<<"username">>, <<"clientid">>};
                                      _ -> {<<"clientid">>, <<"username">>}
                                  end,
            io:format("[INFO] Choosing ~s user-id-type for migrating Internal DB credentials. If you need to migrate ~s instead, "
                      "please re-run the converter with: --user-id-type ~s~n~n",
                      [Chosen, Discarded, Discarded]),
            Chosen
    end;
user_type(_AuthMnesiaData, UserType) ->
    UserType.

convert_acl_mnesia(#{<<"acl_mnesia">> := AclMneisaData}) ->
    KeyFun = fun(#{<<"type">> := <<"all">>}) -> ?ACL_TABLE_ALL;
                (#{<<"type">> := Type0, <<"type_value">> := Val}) ->
                     Type = case Type0 of
                                <<"clientid">> -> ?ACL_TABLE_CLIENTID;
                                <<"username">> -> ?ACL_TABLE_USERNAME
                            end,
                     {Type, Val}
             end,
    GroupedAcl = maps:groups_from_list(KeyFun, AclMneisaData),
    maps:foreach(
      fun(Who, Rules0) ->
              Rules = shrink_acl_rules(lists:map(fun convert_acl_mnesia_rule/1, Rules0)),
              ok = mnesia:dirty_write(#emqx_acl{who = Who, rules = Rules})
      end,
      GroupedAcl);
convert_acl_mnesia(_InutMap) ->
    ok.

convert_acl_mnesia_rule(#{<<"action">> := Action, <<"access">> := Permission, <<"topic">> := Topic}) ->
    {permission(Permission), action(Action), Topic}.

action(<<"pub">>) -> publish;
action(<<"sub">>) -> subscribe.

permission(<<"allow">>) -> allow;
permission(<<"deny">>) -> deny.

shrink_acl_rules(Rules0) ->
    KeyFun = fun({Permission, _Action, Topic}) -> {Permission, Topic} end,
    lists:flatmap(
      %% at this stage, action can only be publish or subscribe
      fun([{Perm, Action1, Topic}, {Perm, Action2, Topic}]) when Action1 =/= Action2 ->
              [{Perm, all, Topic}];
         (Rules) -> Rules
      end,
      maps:values(maps:groups_from_list(KeyFun, Rules0))
     ).

convert_auth_modules(#{<<"modules">> := Modules} = InputMap, Opts) ->
    Mapping = #{<<"mnesia_authentication">> => fun convert_mnesia_auth/2,
                <<"internal_acl">> => fun convert_file_authz/2,
                <<"redis_authentication">> => fun convert_redis_auth/2,
                <<"pgsql_authentication">> => fun convert_pgsql_auth/2,
                <<"mysql_authentication">> => fun convert_mysql_auth/2,
                <<"mongo_authentication">> => fun convert_mongo_auth/2,
                <<"http_authentication">> => fun convert_http_auth/2,
                <<"jwt_authentication">> => fun convert_jwt_auth/2
               },
    {AuthnList, AuthzList} =
        lists:foldr(
          fun(#{<<"type">> := T} = Mod, {AuthnAcc, AuthzAcc}) when is_map_key(T, Mapping) ->
                  HandlerFun = maps:get(T, Mapping),
                  {Authn, Authz} = HandlerFun(Mod, Opts),
                  {[Authn | AuthnAcc], [Authz | AuthzAcc]};
             (_, Acc) -> Acc
          end,
          {[], []},
          Modules),
    FilterFun = fun(undefined) -> false; (#{}) -> true end,
    EmqxHotConf = hotconf(<<"emqx">>, InputMap),
    AuthnOrder = parse_auth_order(maps:get(<<"auth_order">>, EmqxHotConf, <<"none">>)),
    AuthzOrder = parse_acl_order(maps:get(<<"acl_order">>, EmqxHotConf, <<"none">>)),
    AuthnList1 = sort_by_order(lists:filter(FilterFun, AuthnList), AuthnOrder),
    AuthzList1 = sort_by_order(lists:filter(FilterFun, AuthzList), AuthzOrder),
    DenyAction = maps:get(<<"acl_deny_action">>, EmqxHotConf, <<>>),
    NoMatch = maps:get(<<"acl_nomatch">>, EmqxHotConf, <<>>),
    OutAuthzConf = #{<<"sources">> => AuthzList1},
    OutAuthzConf1 = put_unless_empty(<<"deny_action">>, DenyAction, OutAuthzConf),
    OutAuthzConf2 = put_unless_empty(<<"no_match">>, NoMatch, OutAuthzConf1),
    #{<<"authentication">> => AuthnList1,
      <<"authorization">> => OutAuthzConf2};
convert_auth_modules(_InConf, _Opts) ->
    #{}.

hotconf(Name, InputMap) ->
    case InputMap of
        #{<<"configs">> := Configs} ->
            case lists:filter(fun(#{<<"name">> := N}) -> N =:= Name; (_) -> false end, Configs) of
                [#{<<"confs">> := Confs}] -> Confs;
                _ -> #{}
            end;
        _ -> #{}
    end.

sort_by_order(AuthList, Order) ->
    {SortedByOrder, Rem} =
        lists:foldr(fun({Key, Val}, {SortedAcc, RemAuthL}) ->
                            case lists:filter(fun(#{Key := V}) -> V =:= Val; (_) -> false end, RemAuthL) of
                                [Auth] ->
                                    {[Auth | SortedAcc], lists:delete(Auth, RemAuthL)};
                                _ ->
                                    {SortedAcc, RemAuthL}
                            end
                    end,
                    {[], AuthList},
                    Order),
    SortedByOrder ++ Rem.

parse_auth_order(AuthOrder) ->
    parse_auth_acl_order(fun parse_auth_name/1, AuthOrder).

parse_acl_order(AclOrder) ->
    parse_auth_acl_order(fun parse_acl_name/1, AclOrder).

parse_auth_acl_order(NameParser, CSV) when is_function(NameParser) ->
    do_parse_auth_acl_order(NameParser, string:tokens(str(CSV), ", ")).

do_parse_auth_acl_order(_, []) -> [];
do_parse_auth_acl_order(Parser, ["none" | Names]) ->
    %% "none" is the default config value
    do_parse_auth_acl_order(Parser, Names);
do_parse_auth_acl_order(Parser, [Name0 | Names]) ->
    Name = Parser(Name0),
    [Name | do_parse_auth_acl_order(Parser, Names)].

parse_auth_name(Name) ->
    case parse_auth_name1(Name) of
        {T, N} -> {T, N};
        N -> {<<"backend">>, N}
    end.

parse_auth_name1("http") -> <<"http">>;
parse_auth_name1("jwt") -> {<<"mechanism">>, <<"jwt">>};
parse_auth_name1("mnesia") -> <<"built_in_database">>;
parse_auth_name1("mongodb") -> <<"mongodb">>;
parse_auth_name1("mongo") -> <<"mongodb">>;
parse_auth_name1("mysql") ->  <<"mysql">>;
parse_auth_name1("pgsql") -> <<"postgresql">>;
parse_auth_name1("postgres") -> <<"postgresql">>;
parse_auth_name1("redis") -> <<"redis">>;
parse_auth_name1(Other) -> Other.

parse_acl_name(Name) ->
    {<<"type">>, parse_acl_name1(Name)}.

parse_acl_name1("file") -> <<"file">>;
parse_acl_name1("internal") -> <<"file">>;
parse_acl_name1("http") -> <<"http">>;
parse_acl_name1("mnesia") -> <<"built_in_database">>;
parse_acl_name1("mongo") -> <<"mongodb">>;
parse_acl_name1("mongodb") -> <<"mongodb">>;
parse_acl_name1("mysql") -> <<"mysql">>;
parse_acl_name1("pgsql") -> <<"postgresql">>;
parse_acl_name1("postgres") -> <<"postgresql">>;
parse_acl_name1("redis") -> <<"redis">>;
parse_acl_name1(Other) -> Other.

convert_redis_auth(#{<<"enabled">> := IsEnabled, <<"config">> := InConf}, _Opts) ->
    SSL = convert_ssl_opts(InConf),
    #{<<"type">> := RedisType,
      <<"server">> := Server,
      <<"pool_size">> := PoolSize,
      <<"database">> := Database,
      <<"password_hash">> := PasswHash} = InConf,

    OutConf = #{<<"enable">> => IsEnabled,
                <<"redis_type">> => RedisType,
                <<"pool_size">> => PoolSize,
                <<"database">> => Database,
                <<"ssl">> => SSL},
    OutConf1 = case RedisType of
                  <<"single">> ->
                      OutConf#{<<"server">> => Server};
                  <<"cluster">> ->
                       maps:remove(<<"database">>, OutConf#{<<"servers">> => Server});
                  <<"sentinel">> ->
                       SentinelName = maps:get(<<"sentinel">>, InConf),
                       OutConf#{<<"servers">> => Server, <<"sentinel">> => SentinelName}
               end,
    RedisPassw = maps:get(<<"password">>, InConf, <<>>),
    OutConf2 = put_unless_empty(<<"password">>, RedisPassw, OutConf1),

    AclCmd = string:trim(maps:get(<<"acl_cmd">>, InConf, <<>>)),
    AuthnCmd = string:trim(maps:get(<<"auth_cmd">>, InConf, <<>>)),
    SuperCmd = string:trim(maps:get(<<"super_cmd">>, InConf, <<>>)),

    AuthnConf = redis_authn(AuthnCmd, SuperCmd, PasswHash, OutConf2),
    AuthzConf = redis_authz(AclCmd, OutConf2),
    warn_if_no_auth("Redis", AuthnConf, AuthzConf),
    {AuthnConf, AuthzConf}.

redis_authn(<<>> = _AuthnCmd, _SuperCmd, _PasswHash, _Conf) ->
    undefined;
redis_authn(AuthnCmd, SuperCmd, PasswHash, Conf) ->
    case convert_redis_authn_q(AuthnCmd, SuperCmd) of
        undefined ->
            undefined;
        AuthnCmd1 -> Conf#{<<"cmd">> => convert_placeholders(AuthnCmd1),
                           <<"mechanism">> => <<"password_based">>,
                           <<"backend">> => <<"redis">>,
                           <<"password_hash_algorithm">> => convert_passw_hash(PasswHash)
                          }
    end.

redis_authz(<<>> = _AclCmd, _Conf) ->
    undefined;
redis_authz(AclCmd, Conf) ->
    io:format("[WARNING] Redis ACL data must be updated manually to be compatible with EMQX 5.1, "
              "the config will be migrated but it won't work in EMQX 5.1 if data is not changed, "
              "please see more details at: "
              "https://docs.emqx.com/en/enterprise/v5.1/deploy/upgrade-from-v4.html#redis-1.~n~n",
              []),
    Conf#{<<"cmd">> => convert_placeholders(AclCmd),
          <<"type">> => <<"redis">>
         }.

is_supported_redis_cmd("HGET") ->
    true;
is_supported_redis_cmd("HMGET") ->
    true;
is_supported_redis_cmd(Cmd) ->
    io:format("[WARNING] Skipping Redis authentication, as \"auth_cmd\": ~s is not supported by "
              "EMQX 5.x: only HGET and HMGET commands are allowed.~n~n", [Cmd]),
    false.

is_supported_redis_fields(Fields) ->
    HasPassHash = lists:member("password_hash", Fields) orelse lists:member("password", Fields),
    HasPassHash
        orelse io:format("[WARNING] Skipping Redis authentication, as \"auth_cmd\" is not supported "
                         "by EMQX 5.x: fields ~p miss required value: password_hash or "
                         "password.~n~n", [Fields]),
    HasPassHash.

convert_redis_authn_q(AuthnQ, SuperQ) ->
    case string:tokens(str(AuthnQ), " ") of
        [Cmd, Key, F | Fs] ->
            Fields = [F | Fs],
            IsSupported = is_supported_redis_cmd(string:uppercase(Cmd))
                andalso is_supported_redis_fields(Fields),
            case IsSupported of
                true ->
                    Fields1 = maybe_add_is_super_redis_field(Cmd, Key, Fields, SuperQ),
                    bin(lists:join(" ", [Cmd, Key, lists:join(" ", Fields1)]));
                false ->
                    undefined
            end;
         _ ->
            io:format("[WARNING] Skipping Redis authentication, as \"auth_cmd\": ~s is not "
                      "supported by EMQX 5.x. It must use only HGET or HMGET command and include "
                      " password or password_hash field~n~n", [AuthnQ]),
            undefined
    end.

maybe_add_is_super_redis_field(_AuthnCmd, _Key, AuthnFields, <<>> = _SuperQ) ->
    AuthnFields;
maybe_add_is_super_redis_field(AuthnCmd, AuthnKey, AuthnFields, SuperQ) ->
    case string:tokens(str(SuperQ), " ") of
        [Cmd, Key, "is_superuser"] ->
            case string:uppercase(Cmd) =:= AuthnCmd andalso Key =:= AuthnKey of
                true ->
                    AuthnFields ++ ["is_superuser"];
                false ->
                    io:format("[WARNING] Input Redis auth configuration has superuser query: ~s, "
                              "which is not compatible with EMQX 5.x. If you need to give clients "
                              "super-user permissions, please add  is_superuser field to the Redis "
                              "authentication query command and Redis Hash data manually.~n~n",
                              [SuperQ]),
                    AuthnFields
            end
    end.

convert_pgsql_auth(Module, Opts) ->
    convert_sql_auth("PostgreSQL", Module, Opts).

convert_mysql_auth(Module, Opts) ->
    convert_sql_auth("MySQL", Module, Opts).

convert_sql_auth(DBType, #{<<"enabled">> := IsEnabled, <<"config">> := InConf}, _Opts) ->
    SSL = convert_ssl_opts(InConf),
    #{<<"server">> := Server,
      <<"pool_size">> := PoolSize,
      <<"database">> := Database,
      <<"password">> := DBPassw,
      <<"user">> := DBUser,
      <<"password_hash">> := PasswHash} = InConf,
    OutConf = #{<<"enable">> => IsEnabled,
                <<"server">> => Server,
                <<"pool_size">> => PoolSize,
                <<"database">> => Database,
                <<"password">> => DBPassw,
                <<"username">> => DBUser,
                <<"ssl">> => SSL},
    AclQuery =  string:trim(maps:get(<<"acl_query">>, InConf, <<>>)),
    AuthnQuery = string:trim(maps:get(<<"auth_query">>, InConf, <<>>)),
    SuperQuery = string:trim(maps:get(<<"super_query">>, InConf, <<>>)),
    AuthnConf = sql_authn(DBType, AuthnQuery, SuperQuery, PasswHash, OutConf),
    AuthzConf = sql_authz(DBType, AclQuery, OutConf),
    warn_if_no_auth(DBType, AuthnConf, AuthzConf),
    {AuthnConf, AuthzConf}.

%% parses columns and table in basic select queries
parse_sql(Query) ->
    {ok, MP} = re:compile("select\s+(.*)\s+from\s+(.*)\s*(where\s.*)", [caseless]),
    case re:run(string:lowercase(str(Query)), MP, [{capture, all_but_first, list}]) of
        {match, [Columns0, Table, Rem]} ->
            Columns = [string:trim(F) || F <- string:split(Columns0, ",")],
            {ok, {Columns, string:trim(Table), Rem}};
        _ ->
            error
    end.

reconstruct_sql(Columns, Table, Rem) ->
    bin("select " ++ lists:join(", ", Columns) ++ " from " ++ Table ++ " " ++ Rem).

sql_authn(_Type, <<>> = _AuthnQuery, _SuperQuery, _PasswHash, _Conf) ->
    undefined;
sql_authn(Type, AuthnQuery, SuperQuery, PasswHash, Conf) ->
    Query = convert_placeholders(convert_sql_authn_q(Type, AuthnQuery, SuperQuery)),
    Conf#{<<"query">> => Query,
          <<"mechanism">> => <<"password_based">>,
          <<"backend">> => bin(string:lowercase(Type)),
          <<"password_hash_algorithm">> => convert_passw_hash(PasswHash)}.

sql_authz(_Type, <<>> = _AclQuery, _Conf) ->
    undefined;
sql_authz(Type, AclQuery, Conf) ->
    io:format(
      "[WARNING] ~s ACL data and query must be updated manually to be compatible with EMQX 5.1, "
      "the config will be migrated but it won't work in EMQX 5.1 if data/query is not changed, "
      "please see more details at: "
      "https://docs.emqx.com/en/enterprise/v5.1/deploy/upgrade-from-v4.html#mysql-postgresql.~n~n",
      [Type]
     ),
    Conf#{<<"query">> => convert_placeholders(AclQuery),
          <<"type">> => bin(string:lowercase(Type))
         }.

convert_sql_authn_q(Type, AuthnQ, SuperQ) ->
    case parse_sql(AuthnQ) of
        {ok, {Columns, Table, Rem}} ->
            Columns1 = sql_authn_columns(Columns),
            Columns2 = maybe_add_is_super_sql_column(Type, Columns1, Table, SuperQ),
            reconstruct_sql(Columns2, Table, Rem);
        _ ->
            io:format(
              "[WARNING] Failed to parse ~s authentication query: ~s. "
              "It will be converted but may fail to work properly in EMQX 5.1. "
              "Please update the query and/or data manually according to the documentation: "
              "https://docs.emqx.com/en/enterprise/v5.1/deploy/upgrade-from-v4.html#mysql-postgresql.~n~n",
              [Type, AuthnQ]
             ),
            AuthnQ
    end.

maybe_add_is_super_sql_column(_Type, Columns, _Table, <<>> = _SuperQ) ->
    Columns;
maybe_add_is_super_sql_column(Type, Columns, Table, SuperQ) ->
    case parse_sql(SuperQ) of
        {ok, {[IsSuper0], Table, _Rem}} ->
            IsSuper = super_column(IsSuper0),
            Columns ++ [IsSuper];
        _ ->
            io:format("[WARNING] Cannot convert ~s superuser query: ~s. It (probably) uses "
                      "a different table than the main authentication query: ~s.~n~n",
                      [Type, SuperQ, Table]),
            Columns
    end.

sql_authn_columns([Passw, Salt]) ->
    [passw_column(Passw), salt_column(Salt)];
sql_authn_columns([Passw]) ->
    [passw_column(Passw)].

passw_column(P) when P =:= "password"; P =:= "password_hash" -> P;
passw_column(P) -> maybe_add_sql_alias(P, "password_hash").

salt_column("salt" = S) -> S;
salt_column(S) -> maybe_add_sql_alias(S, "salt").

super_column("is_superuser" = S) -> S;
super_column(S) -> maybe_add_sql_alias(S, "is_superuser").

maybe_add_sql_alias(Name, Alias) ->
    case string:find(Name, " as ") of
        nomatch -> Name ++ " as " ++ Alias;
        _ -> Name
    end.

convert_mongo_auth(#{<<"enabled">> := IsEnabled, <<"config">> := InConf}, _Opts) ->
    SSL = convert_ssl_opts(InConf),
    #{<<"type">> := MongoType,
     <<"pool_size">> := PoolSize,
     <<"server">> := Server,
     <<"database">> := DB,
     <<"srv_record">> := SrvRecord
    } = InConf,
    case mongo_type(MongoType, Server, InConf) of
        undefined ->
            undefined;
        OutConf ->
            OutConf1 = OutConf#{<<"enable">> => IsEnabled,
                                <<"ssl">> => SSL,
                                <<"srv_record">> => SrvRecord,
                                <<"pool_size">> => PoolSize,
                                <<"database">> => DB
                               },
            OptionalConf = #{<<"username">> => maps:get(<<"login">>, InConf, <<>>),
                             <<"password">> => maps:get(<<"password">>, InConf, <<>>),
                             <<"auth_source">> => maps:get(<<"auth_source">>, InConf, <<>>),
                             <<"w_mode">> => maps:get(<<"w_mode">>, InConf, <<>>)},
            OutConf2 = maps:merge(OutConf1, maps:filter(fun(_K, V) -> V =/= <<>> end, OptionalConf)),
            OutConf3 = maybe_add_mongo_topology(InConf, OutConf2),
            {mongo_authn(InConf, OutConf3), mongo_authz(InConf, OutConf3)}
    end.

mongo_authz(InConf, OutMongoConf) ->
    Collection = string:trim(maps:get(<<"acl_query_collection">>, InConf, <<>>)),
    Selectors = maps:get(<<"acl_query_selectors">>, InConf, []),
    case {Collection, Selectors} of
        {C, S} when C =/= <<>>, S =/= [] ->
            io:format(
              "[WARNING] EMQX 4.4 MongoDB ACL data schema is not compatible with EMQX 5.1. "
              "The configuration will be migrated but ACL data must be updated manually in MongoDB. "
              "Otherwise, MongoDB authorization won't function properly in EMQX 5.1. Please see more details at: "
              "https://docs.emqx.com/en/enterprise/v5.1/deploy/upgrade-from-v4.html#mongodb.~n~n",
              []
             ),
            Filter = lists:foldl(fun(#{<<"acl_query_selector">> := Sel}, Acc) ->
                                         maps:merge(Acc, convert_mongo_selector(Sel))
                                 end, #{}, Selectors),
            OutMongoConf#{<<"type">> => <<"mongodb">>,
                          <<"collection">> => Collection,
                          <<"filter">> => Filter};
        _ ->
            undefined
    end.

mongo_authn(InConf, OutMongoConf) ->
    Collection = string:trim(maps:get(<<"auth_query_collection">>, InConf, <<>>)),
    PasswHash = string:trim(maps:get(<<"auth_query_password_hash">>, InConf, <<>>)),
    Selector = string:trim(maps:get(<<"auth_query_selector">>, InConf, <<>>)),
    Fields = string:trim(maps:get(<<"auth_query_password_field">>, InConf, <<>>)),
    case Collection of
        <<>> ->
            undefined;
        _ ->
            AuthnConf =
                OutMongoConf#{<<"backend">> => <<"mongodb">>,
                              <<"mechanism">> => <<"password_based">>,
                              <<"password_hash_algorithm">> => convert_passw_hash(PasswHash),
                              <<"collection">> => Collection,
                              <<"filter">> => convert_mongo_selector(Selector)},
            maps:merge(AuthnConf, convert_mongo_fields(Fields))
    end.

maybe_add_mongo_superuser(InConf, AuthnCollection, AuthnConf) ->
    SuperCollection = string:trim(maps:get(<<"super_query_collection">>, InConf, <<>>)),
    SuperField = string:trim(maps:get(<<"super_query_field">>, InConf, <<>>)),
    case {SuperCollection, SuperField} of
        {<<>>, <<>>} ->
            AuthnConf;
        {AuthnCollection, <<>>} ->
            io:format("[INFO] MongoDB auth \"super_query_field\" field is empty, "
                      "default value \"is_superuser\" will be used.~n~n",
                      []),
            AuthnConf#{<<"is_superuser_field">> => <<"is_superuser">>};
        {AuthnCollection, _} ->
            AuthnConf#{<<"is_superuser_field">> => SuperField};
        {SuperCollection, _} ->
            io:format("[WARNING] Separate MongoDB collection is used as \"super_query_collection\", "
                      "which is not compatible with EMQX 5.1. If you need to give clients super-user "
                      "permissions in EMQX 5.1, please add is_superuser field to the main authentication "
                      "collection.~n~n",
                      []),
            AuthnConf
    end.

convert_mongo_selector(Selector) ->
    [Field, Placeholder] = string:split(Selector, <<"=">>),
    #{Field => convert_placeholders(Placeholder)}.

convert_mongo_fields(Fields) ->
    case [string:trim(F) || F <- string:split(Fields, ",")] of
        [PasswF] ->
            #{<<"password_hash_field">> => PasswF};
        [PasswF, SaltF] ->
            #{<<"password_hash_field">> => PasswF,
              <<"salt_field">> => SaltF}
    end.

mongo_type(<<"unknown">> = _Type, _Server, _InConfig) ->
    %%TODO: add CLI opt for this case?
    io:format(
      "[WARNING] Skipping MongoDB auth/acl config because it uses \"unknown\" topology, "
      "which is not compatible with EMQX 5.1. Please set a defined MongoDB topology in the input file "
      "and run the converter again.~n~n",
      []
     ),
    undefined;
mongo_type(<<"single">> = Type, Server, _InConf) ->
    #{<<"server">> => Server,
      <<"mongo_type">> => Type};
mongo_type(<<"rs">> = Type, Server, InConf) ->
    Conf = #{<<"servers">> => Server,
             <<"mongo_type">> => Type},
    put_unless_empty(<<"r_mode">>, maps:get(<<"r_mode">>, InConf, <<>>), Conf);
mongo_type(<<"sharded">> = Type, Server, _InConf) ->
    #{<<"servers">> => Server,
      <<"mongo_type">> => Type}.

maybe_add_mongo_topology(InConf, OutConf) ->
    Topology =
        #{<<"pool_size">> => maps:get(<<"topology_pool_size">>, InConf, <<>>),
          <<"max_overflow">> => maps:get(<<"topology_max_overflow">>, InConf, <<>>),
          <<"overflow_ttl">> => maps:get(<<"topology_overflow_ttl">>, InConf, <<>>),
          <<"overflow_check_period">> => maps:get(<<"topology_overflow_check_period">>, InConf, <<>>),
          <<"local_threshold_ms">> => maps:get(<<"topology_local_threshold_ms">>, InConf, <<>>),
          <<"connect_timeout_ms">> => maps:get(<<"topology_connect_timeout_ms">>, InConf, <<>>),
          <<"socket_timeout_ms">> => maps:get(<<"topology_socket_timeout_ms">>, InConf, <<>>),
          <<"server_selection_timeout_ms">> => maps:get(<<"topology_server_selection_timeout_ms">>, InConf, <<>>),
          <<"wait_queue_timeout_ms">> => maps:get(<<"topology_wait_queue_timeonut_ms">>, InConf, <<>>),
          <<"heartbeat_frequency_ms">> => maps:get(<<"topology_heartbeat_frequency_ms">>, InConf, <<>>),
          <<"min_heartbeat_frequency_ms">> => maps:get(<<"topology_min_heartbeat_frequency_ms">>, InConf, <<>>)
         },
    case maps:filter(fun(_K, V) -> V =/= <<>> end, Topology) of
        EmptyMap when map_size(EmptyMap) =:= 0 ->
            OutConf;
        Map ->
            OutConf#{<<"topology">> => Map}
    end.

convert_http_auth(#{<<"enabled">> := IsEnabled, <<"config">> := InConf}, _Opts) ->
    io:format(
      "[WARNING] EMQX 4.4 HTTP Auth/ACL service behaviour is not compatible with EMQX 5.1.~n"
      "The configuration will be converted but it won't function properly in EMQX 5.1, "
      "until HTTP service behaviour is updated accordingly, please read the documentation for more details:~n"
      "    https://docs.emqx.com/en/enterprise/v5.1/deploy/upgrade-from-v4.html#http~n"
      "    https://docs.emqx.com/en/enterprise/v5.1/deploy/upgrade-from-v4.html#http-1~n"
      "    https://docs.emqx.com/en/enterprise/v5.1/access-control/authn/http.html#post-request~n"
      "    https://docs.emqx.com/en/enterprise/v5.1/access-control/authz/http.html~n~n",
      []),
    SSL = convert_ssl_opts(InConf),
    #{<<"pool_size">> := PoolSize,
      <<"method">> := Method,
      <<"req_content_type">> := ContentType
     } = InConf,
    Headers = maps:get(<<"http_headers">>, InConf, #{}),
    Headers1 = Headers#{<<"content-type">> => ContentType},
    OutConf = #{<<"enable">> => IsEnabled,
                <<"method">> => string:lowercase(Method),
                <<"pool_size">> => PoolSize,
                <<"ssl">> => SSL,
                <<"headers">> => Headers1},
    HTTPOpts = #{<<"request_timeout">> => maps:get(<<"http_opts_timeout">>, InConf, <<>>),
                 <<"max_retries">> => maps:get(<<"http_opts_retry_times">>, InConf, <<>>),
                 <<"enable_pipelining">> => maps:get(<<"http_opts_pipelining">>, InConf, <<>>),
                 <<"connect_timeout">> => maps:get(<<"http_opts_connect_timeout">>, InConf, <<>>)
                },
    HTTPOpts1 = maps:filter(fun(_K, V) when is_binary(V) -> string:trim(V) =/= <<>>; (_, _) -> true end, HTTPOpts),
    OutConf1 = maps:merge(OutConf, HTTPOpts1),
    AuthUrl = string:trim(maps:get(<<"auth_req">>, InConf, <<>>)),
    SuperUrl = string:trim(maps:get(<<"super_req">>, InConf, <<>>)),
    AuthParams = string:trim(maps:get(<<"auth_req_params">>, InConf, <<>>)),
    AclUrl = string:trim(maps:get(<<"acl_req">>, InConf, <<>>)),
    AclParams = string:trim(maps:get(<<"acl_req_params">>, InConf, <<>>)),
    {http_authn(AuthUrl, AuthParams, SuperUrl, OutConf1), http_authz(AclUrl, AclParams, OutConf1)}.

http_authn(AuthUrl, AuthParams, SuperUrl, OutConf) when AuthUrl =/= <<>>, AuthParams =/= <<>> ->
    case SuperUrl of
        <<>> -> ok;
        _ ->
            io:format(
              "[WARNING] EMQX 4.4 HTTP Auth/ACL uses super_req: ~s which is not compatible with EMQX 5.1.~n"
              "If you need to give clients super-user permissions in EMQX 5.1, please add is_superuser "
              "field to the authentication response body.~n~n",
              [SuperUrl])
    end,
    OutConf#{<<"mechanism">> => <<"password_based">>,
             <<"backend">> => <<"http">>,
             <<"url">> => AuthUrl,
             <<"body">> => convert_http_req_params(AuthParams, [])};
http_authn(_AuthUrl, _AuthParams, _SuperUrl, _OutConf) ->
    undefined.

http_authz(AclUrl, AclParams, OutConf) when AclUrl =/= <<>>, AclParams =/= <<>> ->
    Placeholders = [{<<"${proto_name}">>, <<"%r">>},
                    %% "%p" -> sockport not suported in EMQX 5.x?
                    {<<"${action}">>, <<"%A">>},
                    {<<"${topic}">>, <<"%t">>},
                    {<<"${mountpoint}">>, <<"%m">>}],
    OutConf#{<<"type">> => <<"http">>,
             <<"url">> => AclUrl,
             <<"body">> => convert_http_req_params(AclParams, Placeholders)};
http_authz(_AclUrl, _AclParams, _OutConf) ->
    undefined.

convert_http_req_params(Params, ExtraPlaceholders) ->
    lists:foldr(
      fun(KV, Acc) ->
              [K, V] = string:split(string:trim(KV), <<"=">>),
              Acc#{K => V}
      end,
      #{},
      string:split(convert_placeholders(Params, ExtraPlaceholders ++ ?PLACEHOLDERS), <<",">>)
     ).

convert_jwt_auth(#{<<"enabled">> := IsEnabled, <<"config">> := InConf}, Opts) ->
    io:format(
      "[WARNING] JWT authentication module is present in the input file. "
      "It will be converted to EMQX 5.1, but tokens that use EMQX 4.4 placeholders (%u and %c) "
      "in ACL claims are not compatible with EMQX 5.1.~n"
      "For example: ~n"
      "    EMQX 4.4:  {..., \"acl\": {\"pub\": [\"some/stats/%c\"]}, ...}~n"
      "    EMQX 5.1:  {..., \"acl\": {\"pub\": [\"some/stats/${clientid}\"]}, ...}~n"
      "If you use placeholders in token claims, please make sure to update them to EMQX 5.1 format:~n"
      "    %u -> ${username}~n"
      "    %c -> ${clientid}~n~n",
      []),
     #{<<"verify_claims">> := VerifyClaims,
       <<"secret">> := Secret0,
       <<"jwks_addr">> := JWKSAddr0,
       <<"from">> := From,
       <<"claims">> := Claims,
       <<"acl_claim_name">> := AclClaimName
      } = InConf,
    Secret = string:trim(Secret0),
    PubKey = string:trim(maps:get(<<"file">>, maps:get(<<"pubkey">>, InConf, #{}), <<>>)),
    JWKSAddr = string:trim(JWKSAddr0),

    Conf = jwt_type(Secret, PubKey, JWKSAddr, maps:get(jwt_type, Opts)),
    {Conf#{<<"mechanism">> => <<"jwt">>,
          <<"from">> => From,
          <<"enable">> => IsEnabled,
          <<"acl_claim_name">> => AclClaimName,
          <<"verify_claims">> => jwt_claims(VerifyClaims, Claims)
          },
     undefined}.

jwt_claims(true = _VerifyClaims, Claims) ->
    maps:map(
      fun(_Name, <<"%u">>) -> <<"${username}">>;
         (_Name, <<"%c">>) -> <<"${clientid}">>;
         (_Name, Other) -> Other
      end,
      Claims
     );
jwt_claims(_VerifyClaims, _Claims) ->
    #{}.

jwt_type(Secret, PubKey, JWKAddr, UserJwtType) ->
    case UserJwtType of
        <<"jwks">> when JWKAddr =/= <<>> ->
            jwt_jwks_type(JWKAddr);
        <<"public-key">> when PubKey =/= <<>> ->
            jwt_pubkey_type(PubKey);
        <<"hmac-based">> when Secret =/= <<>> ->
            jwt_hmac_type(Secret);
        undefined ->
            jwt_type(Secret, PubKey, JWKAddr);
        T ->
            io:format("[WARNING] Requested JWT authentication type ~s is not configured in the input file, "
                      "falling back to the default precedence: jwks, public-key, hmac-based~n~n",
                      [T]),
            jwt_type(Secret, PubKey, JWKAddr)
    end.

jwt_type(Secret, PubKey, JWKAddr) when JWKAddr =/= <<>> ->
    maybe_warn_unused_jwt("JWKS", [{"HMAC based secret", Secret}, {"Public key", PubKey}]),
    jwt_jwks_type(JWKAddr);
jwt_type(Secret, PubKey, _JWKAddr) when PubKey =/= <<>> ->
    maybe_warn_unused_jwt("Public key", [{"HMAC based secret", Secret}]),
    jwt_pubkey_type(PubKey);
jwt_type(Secret, _PubKey, _JWKAddr) when Secret =/= <<>> ->
    jwt_hmac_type(Secret).

jwt_jwks_type(JWKAddr) ->
    #{<<"ssl">> => #{<<"enable">> => false},
      <<"endpoint">> => JWKAddr,
      <<"use_jwks">> => true
     }.

jwt_pubkey_type(PubKey) ->
    #{<<"algorithm">> => <<"public-key">>,
      <<"public_key">> => PubKey,
      <<"use_jwks">> => false}.

jwt_hmac_type(Secret) ->
     #{<<"algorithm">> => <<"hmac-based">>,
      <<"secret">> => Secret,
      <<"use_jwks">> => false}.

maybe_warn_unused_jwt(_UsedType, UnusedList) ->
    %%TODO: improve message
    [io:format(
       "[WARNING] JWT ~s won't be migrated as EMQX 5.x allows using only one JWT mechanism at a time.~n~n",
       [Name]
      ) || {Name, Val} <- UnusedList, Val =/= <<>>].

convert_mnesia_auth(#{<<"enabled">> := IsEnabled, <<"config">> := InConf}, Opts) ->
    UserIdType = case maps:get(user_id_type, Opts) of
                     %% No CLI opt provided, no Mnesia data in the input file to choose the type:
                     %% fallback to username
                     undefined -> <<"username">>;
                     Type -> Type
                 end,
    #{<<"password_hash">> := HashFunName} = InConf,
    AuthnConf = #{<<"enable">> => IsEnabled,
                  <<"backend">> => <<"built_in_database">>,
                  <<"mechanism">> => <<"password_based">>,
                  <<"password_hash_algorithm">> =>
                      #{<<"name">> => HashFunName,
                        <<"salt_position">> => <<"prefix">>},
                  <<"user_id_type">> => UserIdType},
    AuthzConf = #{<<"enable">> => IsEnabled, <<"type">> => <<"built_in_database">>},
    {AuthnConf, AuthzConf}.

warn_if_no_auth(Type, undefined, undefined) ->
    io:format("[WARNING] Skipping ~s Authn/Acl configuration as both acl query and auth query "
                      "\"auth_cmd\" are empty. Such configuration would fail to load in EMQX 5.1, "
                      "as cmd/query is a required field.~n~n",
              [Type]);
warn_if_no_auth(_Type, _Authn, _Authz) ->
    ok.

convert_file_authz(#{<<"enabled">> := IsEnabled, <<"config">> := Conf}, Opts) ->
    Authn = undefined,
    Authz = case Conf of
                #{<<"acl_rule_file">> := #{<<"file">> := FileContent}} ->
                    convert_acl_rules(IsEnabled, string:trim(FileContent), Opts);
                _ ->
                    io:format("[WARNING] Skipping ACL file authorization, as ACL file is missing.~n",
                              []),
                    undefined
            end,
    {Authn, Authz}.

convert_acl_rules(_IsEnabled, <<>> = _AclRules, _Opts) ->
    io:format("[WARNING] Skipping ACL file authorization, as ACL file content is empty.~n~n", []),
    undefined;
convert_acl_rules(IsEnabled, AclRulesBin, Opts) ->
    TmpFile = filename:join(maps:get(output_dir, Opts), "acl.conf"),
    try
        ok = file:write_file(TmpFile, AclRulesBin),
        {ok, AclRules0} = file:consult(TmpFile),
        AclRules = lists:map(
                     fun({Permission, Who, Action, Topics}) ->
                             Rule = {Permission, Who, convert_action(Action), convert_topics(Topics)},
                             io_lib:format("~p.~n~n", [Rule]);
                        (AllRule) ->
                             io_lib:format("~p.~n~n", [AllRule])
                     end,
                     AclRules0),
        AclRules1 = iolist_to_binary([?ACL_FILE_COMMENTS | AclRules]),
        #{<<"enable">> => IsEnabled,
          <<"type">> => <<"file">>,
          <<"rules">> => AclRules1}
    catch
        _:Reason:St ->
            io:format("[ERROR] failed to convert ACL file, reason: ~p, stacktrace: ~p~n~n",
                      [Reason, St]),
            undefined
    after
        file:delete(TmpFile)
    end.

convert_action(subscribe) -> subscribe;
convert_action(publish) -> publish;
convert_action(pubsub) -> all.

convert_topics(Topics) when is_list(Topics) ->
    [convert_topic(T) || T <- Topics];
convert_topics(Topic) ->
    %% EMQX 5 supports lists only
    [convert_topic(Topic)].

convert_topic({eq, Topic}) -> {eq, Topic};
convert_topic(Topic) ->
    lists:foreach(
      fun(UnsupportedTmpl) ->
              case binary:match(bin(Topic), UnsupportedTmpl) of
                  nomatch -> ok;
                  _Found ->
                      io:format("[WARNING] ACL file contains \"~s\" placeholder in the topic filter: "
                                "\"~s\", which is not supported in EMQX 5.1. "
                                "ACL file will be migrated but it will require a manual correction "
                                "after importing to EMQX 5.1 in order to function properly.~n~n",
                                [UnsupportedTmpl, Topic])
              end
      end,
      [<<"%cna">>, <<"%cida">>]
     ),
    Placeholders = [{<<"${username}">>, <<"%u">>}, {<<"${clientid}">>, <<"%c">>}],
    str(convert_placeholders(bin(Topic), Placeholders)).

convert_placeholders(Str) ->
    convert_placeholders(Str, ?PLACEHOLDERS).

convert_placeholders(Str, Placeholders) ->
    lists:foldl(
      fun({ToTempl, FromTempl}, Acc) ->
              re:replace(Acc, <<"'?", FromTempl/binary, "'?">>, ToTempl, [{return, binary}, global])
      end,
      Str,
      Placeholders).

convert_passw_hash(PassHash) ->
    case binary:split(PassHash, <<",">>) of
        [<<"salt">>, HashFunName] ->
            hash_algoritm(<<"prefix">>, HashFunName);
        [HashFunName, <<"salt">>] ->
            hash_algoritm(<<"suffix">>, HashFunName);
        [HashFunName] ->
            hash_algoritm(<<"disable">>, HashFunName)
    end.

hash_algoritm(SaltPos, HashFunName) ->
    #{<<"name">> => HashFunName,
      <<"salt_position">> => SaltPos}.

convert_ssl_opts(#{<<"ssl">> := false} = _InConf) ->
    #{<<"enable">> => false};
convert_ssl_opts(#{<<"ssl">> := true} = InConf) ->
    SSL = convert_ssl_files(InConf, #{<<"enable">> => true}),
    Verify = case maps:get(<<"verify">>, InConf, false) of
                 true -> <<"verify_peer">>;
                 false -> <<"verify_none">>
             end,
    %% seems to be available only for Mongo in EMQX4.4
    SNI = maps:get(<<"server_name_indication">>, SSL, <<>>),
    put_unless_empty(<<"server_name_indication">>, SNI, SSL#{<<"verify">> => Verify}).

convert_ssl_files(InConf, SSL) ->
    Keys = [<<"cacertfile">>, <<"certfile">>, <<"keyfile">>],
    lists:foldl(fun(Key, Acc) -> convert_ssl_file(Key, InConf, Acc) end, SSL, Keys).

convert_ssl_file(Key, InConf, SSL) ->
    case InConf of
        #{Key := #{<<"file">> := Content}} when Content /= <<>> ->
            SSL#{Key => Content};
        _ -> SSL
    end.

put_unless_empty(_Key, <<>>, Map) ->
    Map;
put_unless_empty(Key, Val, Map) ->
    Map#{Key => Val}.

str(Data) when is_atom(Data) ->
    atom_to_list(Data);
str(Data) ->
    unicode:characters_to_list(Data).

bin(Data) when is_atom(Data) ->
    atom_to_binary(Data, utf8);
bin(Data) ->
    unicode:characters_to_binary(Data).

local_datetime(MillisecondTs) ->
    calendar:system_time_to_local_time(MillisecondTs, millisecond).
