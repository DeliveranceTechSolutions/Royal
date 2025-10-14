-module(royal_mnesia).

-export([bootstrap/0, ensure_tables/0]).
-include_lib("kernel/include/file.hrl").

-record(session, {id, user_id, data, expires_at}).
-record(flag,    {key, value}).
-record(kvcache, {key, val, ttl_until}).

bootstrap() ->
    application:ensure_all_started(mnesia),
    Nodes = nodes() ++ [node()],
    case mnesia:create_schema(Nodes) of
        {error,{_,{already_exists,_}}} -> ok;
        ok -> ok;
        {error, Reason} -> exit({schema_error, Reason})
    end,
    mnesia:start(),
    ensure_tables(),
    mnesia:wait_for_tables([session, flag, kvcache], 5000),
    ok.

ensure_tables() ->
    create_if_missing(session,  [{attributes, record_info(fields, session)},
                                 {disc_copies, [node()]}]),
    create_if_missing(flag,     [{attributes, record_info(fields, flag)},
                                 {ram_copies, [node()]}]),
    create_if_missing(kvcache,  [{attributes, record_info(fields, kvcache)},
                                 {ram_copies, [node()]}]),
    create_if_missing(user,  [{attributes, record_info(fields, kvcache)},
                                 {ram_copies, [node()]}]),
    ok.

create_if_missing(Tab, Props) ->
    case mnesia:create_table(Tab, Props) of
        {aborted,{already_exists,Tab}} -> ok;
        {atomic, ok} -> ok;
        Other -> exit({table_error, Tab, Other})
    end.

