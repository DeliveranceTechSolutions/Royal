-module(user_session).
-export([
    refresh_tokens/2,
    get_jwt_secret/0,
    fallback_dev_secret/0,
    issue_token/1
]).

get_jwt_secret() ->
    case os:getenv("ROYAL_JWT_SECRET") of
        false -> fallback_dev_secret();  % dev-only fallback
        B64   -> base64:decode(B64)      % -> <<…binary bytes…>>
    end.

fallback_dev_secret() ->
    %% DEV ONLY: per-boot random; rotate restarts invalidate tokens
    crypto:strong_rand_bytes(32).

issue_token(Username) ->
    {ok, Token} = royal_jwt:issue(
        Username, 
        get_jwt_secret(),
        #{
            aud => <<"royal-api">>, 
            ttl => 900
         }
    ),
    {ok, Token}.

refresh_tokens(A,R) ->
    io:format(A),
    io:format(R),
    ok.

