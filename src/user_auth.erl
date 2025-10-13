-module(user_auth).
-export([verify_credentials/2]).

verify_credentials(U, P) ->
    verify_user(U, P).

verify_user(<<"kirk">>, <<"pass">>) -> 
    {ok, Token} = royal_jwt:issue(
        <<"user-123">>, 
        user_session:get_jwt_secret(),
        #{
            aud => <<"royal-api">>, 
            ttl => 900
         }
    ),
    {ok, Token};

verify_user(_, _) -> {error, invalid}.
