%% user_session.erl
-module(user_session).

-include_lib("kernel/include/logger.hrl").

%% ========= API =========
-export([
    get_jwt_secret/0,
    fallback_dev_secret/0,

    %% Login: issue access + refresh (and store refresh)
    issue_tokens/2,          %% (UserId :: binary() | integer(), ClientId :: binary()) -> {ok, AccessJwt, RefreshB64}

    %% Verify access JWT
    authenticate_access/1,   %% (AccessJwt :: binary()) -> ok | {error, term()}

    %% Refresh: rotate refresh, mint new access + refresh
    refresh_tokens/1         %% (RefreshB64 :: binary()) -> {ok, AccessJwt, RefreshB64} | {error, term()}
]).

%% ========= Records =========
-record(refresh, {
    hash,                   %% sha256(refresh_bytes) -- PRIMARY KEY
    jti,                    %% uuid (binary/text)
    user_id,                %% binary()
    client_id,              %% binary()
    issued_at,              %% integer() seconds
    exp_at,                 %% integer() seconds
    revoked_at = undefined, %% integer() | undefined
    parent_hash = undefined %% for reuse/replay tracking
}).

-record(session, {
    id              :: integer(),   %% unique session id
    user_id         :: binary(),    %% who owns the session
    refresh_token   :: binary(),    %% SHA-256(refresh_bytes) 32-byte binary
    expires_at      :: integer()    %% unix epoch seconds
}).

%% ========= Config / Secrets =========
%% Returns {ok, SecretBin}. Uses ROYAL_JWT_SECRET as-is if present,
%% otherwise tries ROYAL_JWT_SECRET_B64, else falls back to a dev secret.
get_jwt_secret() ->
    case os:getenv("ROYAL_JWT_SECRET") of
        false -> fallback_dev_secret();
        Secret -> binary:trim(unicode:characters_to_binary(Secret), both, <<"\s\r\n\t">>)
    end.

fallback_dev_secret() ->
    %% Fixed secret for development (tokens persist across restarts)
    <<"dev-secret-key-32-bytes-long-for-jwt">>.

now_s() -> erlang:system_time(second).

%% ========= Mnesia bootstrapping =========
ensure_mnesia() ->
    _ = (catch mnesia:create_schema([node()])),
    ok = mnesia:start(),
    %% refresh table
    case (catch mnesia:table_info(refresh, attributes)) of
        [_|_] -> ok;
        _ ->
            {atomic, ok} = mnesia:create_table(refresh, [
                {attributes, record_info(fields, refresh)},
                {type, set},
                {disc_copies, [node()]}
            ]),
            ok
    end,
    %% session table
    case (catch mnesia:table_info(session, attributes)) of
        [_|_] -> ok;
        _ ->
            {atomic, ok} = mnesia:create_table(session, [
                {attributes, record_info(fields, session)},
                {type, set},
                {disc_copies, [node()]}
            ]),
            ok
    end.

%% ========= Helpers =========
sha256(B) -> crypto:hash(sha256, B).

new_refresh_bytes() -> crypto:strong_rand_bytes(32).

new_uuid16() ->
    %% For demo, 16 random bytes as JTI (or use uuid lib)
    crypto:strong_rand_bytes(16).

%% Accepts binary() or list(); returns {ok, binary()} | {error, bad_refresh_format}
-spec decode_b64(binary() | list()) -> {ok, binary()} | {error, bad_refresh_format}.
decode_b64(Bin) when is_binary(Bin) ->
    try base64:decode(Bin) of
        RB when is_binary(RB) -> {ok, RB}
    catch
        error:badarg -> {error, bad_refresh_format}
    end;
decode_b64(List) when is_list(List) ->
    decode_b64(unicode:characters_to_binary(List)).

%% ========= Public: Issue on login =========
-spec issue_tokens(binary() | integer(), binary()) ->
        {ok, binary(), binary()} | {error, term()}.
issue_tokens(UserId, ClientId) ->
    %% Get secret
    erlang:display("issue_tokens"),
    Secret = get_jwt_secret(),
    erlang:display("got jwt"),

    %% Access token (short-lived, 15 min)
    {ok, AccessJwt, _Hdrs} =
        royal_jwt:issue(Secret, #{
            aud => <<"royal-api">>,
            ttl => 900,
            sub => UserId
        }),

    erlang:display("got access jwt"),

    %% Refresh token material (30 days)
    RB   = new_refresh_bytes(),      %% raw random bytes (never store raw)
    Hash = sha256(RB),               %% store hash only
    Jti  = new_uuid16(),
    Now  = now_s(),
    Exp  = Now + 30*24*3600,

    %% Build records (DO NOT open a tx here; let caller wrap if needed)
    RefreshRec = #refresh{
        hash       = Hash,
        jti        = Jti,
        user_id    = UserId,
        client_id  = ClientId,
        issued_at  = Now,
        exp_at     = Exp
    },
    SessionId = erlang:unique_integer([monotonic, positive]),
    SessionRec = #session{
        id            = SessionId,
        user_id       = UserId,
        refresh_token = Hash,
        expires_at    = Exp
    },

    %% Persist:
    erlang:display("writing refresh and sesh"),
    Persist = fun() ->
        ok = mnesia:write(RefreshRec),
        ok = mnesia:write(SessionRec),
        ok
    end,
    case mnesia:is_transaction() of
        true  -> ok = Persist();
        false ->
            ensure_mnesia(),
            case mnesia:transaction(Persist) of
                {atomic, ok}   -> ok;
                {aborted, Rsn} -> throw({db_error, Rsn})
            end
    end,

    erlang:display("finished writing refresh and sesh"),
    %% Return Access + base64 refresh for client storage
    {ok, AccessJwt, base64:encode(RB)}.

%% ========= Public: Verify access token =========
-spec authenticate_access(binary()) -> ok | {error, term()}.
authenticate_access(AccessJwt) ->
    Secret = get_jwt_secret(),
    case royal_jwt:verify(AccessJwt, Secret, #{aud => <<"royal-api">>}) of
        {ok, _Claims} -> ok;
        {error, Reason} -> {error, Reason};
        _ -> {error, invalid_access}
    end.

%% ========= Public: Refresh w/ rotation =========
%% Takes base64-encoded refresh token, rotates it, and returns new tokens.
-spec refresh_tokens(binary()) ->
        {ok, Access :: binary(), Refresh :: binary()} | {error, term()}.
refresh_tokens(RefreshBin) ->
    ensure_mnesia(),
    Secret = get_jwt_secret(),
    Now = now_s(),
    %% Decode the base64 refresh token to raw bytes
    case decode_b64(RefreshBin) of
        {ok, RawBytes} ->
            Hash = sha256(RawBytes),
            case mnesia:transaction(fun() ->
                         %% Find session by refresh hash
                         case mnesia:match_object(#session{refresh_token = Hash, _ = '_'}) of
                             [] ->
                                 not_found;
                             [S = #session{user_id = UserId, expires_at = Exp}] when Exp > Now ->
                                 NewRef     = new_refresh_bytes(),     %% rotate
                                 NewRefHash = sha256(NewRef),
                                 NewExp     = Now + 30*24*3600,
                                 mnesia:write(S#session{refresh_token = NewRefHash, expires_at = NewExp}),
                                 {rotated, UserId, NewRef};
                             [_] ->
                                 expired_or_bad
                         end
                     end) of
                {atomic, {rotated, UserId, NewRef}} ->
                    {ok, Access2, _} =
                        royal_jwt:issue(Secret, #{aud => <<"royal-api">>, ttl => 900, sub => UserId}),
                    {ok, Access2, base64:encode(NewRef)};
                {atomic, not_found}      -> {error, invalid_refresh};
                {atomic, expired_or_bad} -> {error, invalid_refresh};
                {aborted, Reason}        -> {error, {mnesia, Reason}}
            end;
        {error, _} ->
            {error, invalid_refresh}
    end.
