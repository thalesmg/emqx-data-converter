%% The #message{} record from different emqx versions
-define(message_4_4(ID, QOS, FROM, FLAGS, HEADERS, TOPIC, PAYLOAD, TIMESTAMP),
        {message, ID, QOS, FROM, FLAGS, HEADERS, TOPIC, PAYLOAD, TIMESTAMP}).

-define(message_5(ID, QOS, FROM, FLAGS, HEADERS, TOPIC, PAYLOAD, TIMESTAMP, EXTRA),
        {message, ID, QOS, FROM, FLAGS, HEADERS, TOPIC, PAYLOAD, TIMESTAMP, EXTRA}).

-type user_group() :: binary().
-type user_id() :: binary().

-record(user_info,
        {user_id :: {user_group(), user_id()},
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

-record(emqx_acl,
        {who :: ?ACL_TABLE_ALL | {?ACL_TABLE_USERNAME, binary()} | {?ACL_TABLE_CLIENTID, binary()},
         rules :: rules()
        }).

-record(retained_message, {topic, msg, expiry_time}).

-record(banned,
        {who :: {clientid, binary()}
              | {peerhost, inet:ip_address()}
              | {username, binary()},
         by :: binary(),
         reason :: binary(),
         at :: integer(),
         until :: integer()
        }).

-record(psk_entry,
        {psk_id :: binary(),
         shared_secret :: binary(),
         extra :: term()
        }).

-record(emqx_app,
        {name = <<>> :: binary() | '_',
         api_key = <<>> :: binary() | '_',
         api_secret_hash = <<>> :: binary() | '_',
         enable = true :: boolean() | '_',
         desc = <<>> :: binary() | '_',
         expired_at = 0 :: integer() | undefined | infinity | '_',
         created_at = 0 :: integer() | '_'
        }).
