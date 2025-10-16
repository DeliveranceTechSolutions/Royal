-module(user_session).
-export([
    refresh_tokens/2,
    get_jwt_secret/0,
    fallback_dev_secret/0,
    issue_token/1,
    authenticate_user/2
]).

get_jwt_secret() ->
    case os:getenv("ROYAL_JWT_SECRET") of
        false -> fallback_dev_secret();  % dev-only fallback
        B64   -> base64:decode(B64)      % -> <<…binary bytes…>>
    end.

fallback_dev_secret() ->
    %% DEV ONLY: per-boot random; rotate restarts invalidate tokens
    crypto:strong_rand_bytes(32).

-spec authenticate_user(binary(), binary()) -> ok | error.
authenticate_user(Token, Refresh) ->
    case royal_jwt:verify(
         Token, 
         Refresh, 
         get_jwt_secret(),
        #{
            aud => <<"royal-api">>, 
            ttl => 900
         }
    ) of
        {ok, Claims} ->
            case royal_jwt:validate_claims(
               Claims, 
               <<"royal">>, 
               <<"royal-api">>, 
               30
            ) of
                ok -> ok;
                error -> error
            end;
        {error, _Term} ->
            error
    end.

issue_token(Username) ->
    {ok, Token, Refresh} = royal_jwt:issue(
        Username, 
        get_jwt_secret(),
        #{
            aud => <<"royal-api">>, 
            ttl => 900
         }
    ),
    {ok, Token, Refresh}.

refresh_tokens(A,R) ->
    io:format(A),
    io:format(R),
    ok.

