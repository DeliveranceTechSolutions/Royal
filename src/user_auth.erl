-module(user_auth).
-export([signup/5, verify_credentials/2]).

-include_lib("stdlib/include/qlc.hrl").

-record(user, {username, id, firstname, lastname, email, password_hash}).
%-record(signup, {id, firstname, lastname, email, username, password}).

verify_credentials(U, P) ->
    verify_user(U, P).

verify_user(U, P) when
      is_binary(U), byte_size(U) > 0,
      is_binary(P), byte_size(P) > 0 ->
    F = fun() ->
            mnesia:read(user, U, read)             % or the correct key
        end,
    case mnesia:transaction(F) of
        {atomic, [#user{password_hash = P} = Rec]} -> {ok, Rec};
        {atomic, [_]}                               -> {error, bad_password};
        {atomic, []}                                -> {error, not_found};
        {aborted, R}                                -> {error, {mnesia, R}}
    end;

%verify_user(<<"kirk">>, <<"pass">>) -> 
%    {ok, Token} = royal_jwt:issue(
%        <<"user-123">>, 
%        user_session:get_jwt_secret(),
%        #{
%            aud => <<"royal-api">>, 
%            ttl => 900
%         }
%    ),
%    {ok, Token};

verify_user(_, _) -> {error, invalid}.

signup(F, L, E, U, P) when
      is_binary(F), byte_size(F) > 0,
      is_binary(L), byte_size(L) > 0,
      is_binary(E), byte_size(E) > 0,
      is_binary(U), byte_size(U) > 0,
      is_binary(P), byte_size(P) > 0 ->
    Fn = fun() ->
            case mnesia:read(user, U, write) of
                [] ->
                    Id = erlang:unique_integer([monotonic, positive]),
                    ok = mnesia:write(#user{
                        username     = U,
                        id           = Id,
                        firstname    = F,
                        lastname     = L,
                        email        = E,
                        password_hash= P     %% TODO: store a hash, not plaintext
                    }),
                    mnesia:read(user, U, read);   %% -> [#user{...}]
                _ ->
                    mnesia:abort({username_taken, U})
            end
         end,
    case mnesia:transaction(Fn) of
        {atomic, [Rec]}                -> {ok, Rec};
        {aborted, {username_taken, _}} -> {error, username_taken};
        {aborted, R}                   -> {error, {mnesia, R}}
    end.
