-module(royal_mnesia).

-export([ensure_tables/0, bootstrap/0, create/2]).
% -include_lib("kernel/include/file.hrl").

%-record(session, {id, user_id, data, expires_at}).
%-record(flag,    {key, value}).
%-record(kvcache, {key, val, ttl_until}).
%
%%% royal_mnesia.erl
%%%

-record(refresh, {
  hash,             %% sha256(refresh_bytes)  -- PRIMARY KEY
  jti,              %% uuid (binary() or text)
  user_id,          %% binary()
  client_id,        %% binary()
  issued_at,        %% integer() seconds
  exp_at,           %% integer() seconds
  revoked_at = undefined, %% integer() | undefined
  parent_hash = undefined %% for reuse/replay tracking
}).

bootstrap() ->
    ensure_named_node(),
    ok = ensure_schema(),
    ok = start_mnesia(),
    ok = ensure_tables().

ensure_named_node() ->
    case node() of
        nonode@nohost -> exit({mnesia_requires_named_node, "start with --sname or --name"});
        _ -> ok
    end.

ensure_schema() ->
    case mnesia:create_schema([node()]) of
        ok -> ok;
        {error, {_, {already_exists, _}}} -> ok;
        {aborted, {already_exists, _}} -> ok;
        Other -> exit({schema_error, Other})
    end.

start_mnesia() ->
    {ok, _} = application:ensure_all_started(mnesia),
    ok.

ensure_tables() ->
    create(refresh,  [hash, jti, user_id, client_id, issues_at, exp_at, revoked_at, parent_hash]),
    create(session,  [id, user_id, refresh_token, expires_at]),
    create(posts,  [author, title, details, user_lat_lng, dest_lat_lng, id]),
    create(user,     [username, id, firstname, lastname, email, password_hash, salt]),
    mnesia:create_table(refresh, [{type, set},{attributes, record_info(fields, refresh)}]),
    mnesia:wait_for_tables([session, user], 10000).

create(Tab, Attrs) ->
    case mnesia:create_table(Tab, [
            {attributes, Attrs},
            {type, set},
            {disc_copies, [node()]}
        ]) of
        {atomic, ok} -> ok;
        {aborted, {already_exists, Tab}} -> ok;
        Other -> exit({table_error, Tab, Other})
    end.

