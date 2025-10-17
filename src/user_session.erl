%% user_session.erl
-module(user_session).
-compile(export_all).

-include_lib("kernel/include/logger.hrl").

%% ========= API =========
-export([
  get_jwt_secret/0,
  fallback_dev_secret/0,

  %% Login: issue access + refresh (and store refresh)
  issue_tokens/2,          %% (UserId :: binary(), ClientId :: binary()) -> {ok, AccessJwt, RefreshB64}

  %% Verify access JWT
  authenticate_access/1,   %% (AccessJwt :: binary()) -> ok | {error, term()}

  %% Refresh: rotate refresh, mint new access + refresh
  refresh_tokens/1         %% (UserId :: binary(), RefreshB64 :: binary()) -> {ok, AccessJwt, RefreshB64} | {error, term()}
]).

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

-record(session, {
    id              :: integer(),   %% unique session id (e.g., unique_integer/1)
    user_id         :: binary(),    %% who owns the session (can be <<"anon">>)
    refresh_token   :: binary(),    %% SHA-256(refresh_bytes) 32-byte binary
    expires_at      :: integer()    %% unix epoch seconds
}).


%% ========= Config / Secrets =========
get_jwt_secret() ->
  case os:getenv("ROYAL_JWT_SECRET") of
    false -> fallback_dev_secret();          %% DEV ONLY
    B64   -> base64:decode(B64)
  end.

fallback_dev_secret() ->
  %% Per-boot random; DEV only (tokens invalidated on restart)
  crypto:strong_rand_bytes(32).

now_s() -> erlang:system_time(second).

%% ========= Mnesia bootstrapping =========
ensure_mnesia() ->
  _ = (catch mnesia:create_schema([node()])),
  ok = mnesia:start(),
  case mnesia:table_info(refresh, attributes) of
    [_|_] -> ok;
    _ ->
      {atomic, ok} = mnesia:create_table(refresh, [
        {attributes, record_info(fields, refresh)},
        {type, set},
        {disc_copies, [node()]}
      ]),
      ok
  end.

%% ========= Helpers =========
sha256(B) -> crypto:hash(sha256, B).

new_refresh_bytes() -> crypto:strong_rand_bytes(32).

new_uuid16() ->
  %% If you use okeuday/uuid: uuid:get_v4().
  %% Using 16 random bytes is fine as a jti for demo:
  crypto:strong_rand_bytes(16).

%% ========= Public: Issue on login =========
-spec issue_tokens(binary(), binary()) -> {ok, binary(), binary()} | {error, term()}.
issue_tokens(ClientId) ->
  ensure_mnesia(),
  Secret = get_jwt_secret(),
  %% Short-lived access (e.g., 15 minutes)
  {ok, AccessJwt} =
    royal_jwt:issue(Secret, #{aud => <<"royal-api">>, ttl => 900}),
  %% Long-lived refresh (e.g., 30 days)
  RB    = new_refresh_bytes(),
  Hash  = sha256(RB),
  Jti   = new_uuid16(),
  Now   = now_s(),
  Exp   = Now + 30*24*3600,
  {atomic, ok} = mnesia:transaction(fun() ->
    mnesia:write(#refresh{
      hash = Hash, jti = Jti, user_id = UserId, client_id = ClientId,
      issued_at = Now, exp_at = Exp
    })
  end),
  {ok, AccessJwt, base64:encode(RB)}.

%% ========= Public: Verify access token =========
-spec authenticate_access(binary()) -> ok | {error, term()}.
authenticate_access(AccessJwt) ->
  Secret = get_jwt_secret(),
  case royal_jwt:verify(AccessJwt, Secret, #{aud => <<"royal-api">>}) of
    {ok, Claims} ->
      case royal_jwt:validate_claims(Claims, <<"royal">>, <<"royal-api">>, 30) of
        ok    -> ok;
        Error -> {error, Error}
      end;
    Error -> {error, Error}
  end.

-spec decode_b64(binary() | list()) -> {ok, binary()} | {error, bad_refresh_format}.
decode_b64(Bin) when is_binary(Bin) ->
    try base64:decode(Bin) of
        RB when is_binary(RB) -> {ok, RB}
    catch
        error:badarg -> {error, bad_refresh_format}
    end;

decode_b64(List) when is_list(List) ->
    decode_b64(unicode:characters_to_binary(List)).

%% ========= Public: Refresh w/ rotation =========
%% refresh_tokens/1: lookup by raw refresh string, rotate in place
-spec refresh_tokens(binary()) ->
        {ok, Access :: binary(), Refresh :: binary()} | {error, term()}.
refresh_tokens(RefreshBin) ->
    ensure_mnesia(),
    Secret = get_jwt_secret(),
    Now    = now_s(),
    case mnesia:transaction(fun() ->
             %% index on session.refresh_token recommended (see note below)
             case mnesia:index_read(session, RefreshBin, refresh_token) of
               [] ->
                 not_found;
               [S = #session{user_id = UserId, expires_at = Exp}] when Exp > Now ->
                 {Access, NewRef} = 
                 NewRef = new_refresh_string(),              %% rotate
                 NewExp = Now + 30*24*3600,
                 mnesia:write(S#session{refresh_token = NewRef, expires_at = NewExp}),
                 {rotated, UserId, NewRef};
               [_] ->
                 expired_or_bad
             end
         end) of
        {atomic, {rotated, UserId, NewRef}} ->
            {ok, Access2} =
                royal_jwt:issue(UserId, Secret, #{aud => <<"royal-api">>, ttl => 900}),
            {ok, Access2, NewRef};
        {atomic, not_found}       -> {error, invalid_refresh};
        {atomic, expired_or_bad}  -> {error, invalid_refresh};
        {aborted, Reason}         -> {error, {mnesia, Reason}}
    end.
