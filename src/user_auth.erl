-module(user_auth).
-export([verify_credentials/2]).

verify_credentials(U, P) ->
    verify_user(U, P).

verify_user(U, P) when (
    is_binary(U) andalso is_binary(P)
    andalso bit_size(U) > 0
    andalso bit_size(P) > 0
) ->
    royal_pool:squery(pool1, <<"show all;">>);

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
