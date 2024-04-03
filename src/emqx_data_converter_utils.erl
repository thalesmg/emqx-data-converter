-module(emqx_data_converter_utils).

-export([random_id/1, deep_merge/2]).

random_id(Len) ->
    BitLen = Len * 4,
    <<R:BitLen>> = crypto:strong_rand_bytes(Len div 2),
    list_to_binary(int_to_hex(R, Len)).

%% #{a => #{b => 3, c => 2}, d => 4}
%%  = deep_merge(#{a => #{b => 1, c => 2}, d => 4}, #{a => #{b => 3}}).
-spec deep_merge(map(), map()) -> map().
deep_merge(BaseMap, NewMap) ->
    NewKeys = maps:keys(NewMap) -- maps:keys(BaseMap),
    MergedBase = maps:fold(
        fun(K, V, Acc) ->
            case maps:find(K, NewMap) of
                error ->
                    Acc#{K => V};
                {ok, NewV} when is_map(V), is_map(NewV) ->
                    Acc#{K => deep_merge(V, NewV)};
                {ok, NewV} ->
                    Acc#{K => NewV}
            end
        end,
        #{},
        BaseMap
    ),
    maps:merge(MergedBase, maps:with(NewKeys, NewMap)).

%%====================================================================
%% Internal functions
%%====================================================================
int_to_hex(I, N) when is_integer(I), I >= 0 ->
    int_to_hex([], I, 1, N).

int_to_hex(L, I, Count, N)
    when I < 16 ->
    pad([int_to_hex(I) | L], N - Count);
int_to_hex(L, I, Count, N) ->
    int_to_hex([int_to_hex(I rem 16) | L], I div 16, Count + 1, N).

int_to_hex(I) when 0 =< I, I =< 9 ->
    I + $0;
int_to_hex(I) when 10 =< I, I =< 15 ->
    (I - 10) + $a.

pad(L, 0) ->
    L;
pad(L, Count) ->
    pad([$0 | L], Count - 1).
