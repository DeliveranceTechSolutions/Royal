-module(user_auth).
-export([signup/5, verify_credentials/2]).

-include_lib("stdlib/include/qlc.hrl").

-record(user, {username, id, firstname, lastname, email, password_hash, salt}).
%-record(signup, {id, firstname, lastname, email, username, password}).

verify_credentials(U, P) ->
    verify_user(U, P).

verify_user(U, P) when
      is_binary(U), byte_size(U) > 0,
      is_binary(P), byte_size(P) > 0 ->
    F = fun() ->
            case mnesia:read(user, U, read) of
                [#user{password_hash = StoredHash, salt = StoredSalt}] ->
                    case bcrypt:hashpw(P, StoredSalt) of
                        {ok, Hash} when Hash =:= StoredHash ->
                            ok;                   
                        {ok, _Other} ->
                            bad_password;        
                        {error, Why} ->
                            {hash_failed, Why}     
                    end;
                [] ->
                    not_found
            end
        end,

    case mnesia:transaction(F) of
        {atomic, ok}                 -> user_session:issue_token(U);
        {atomic, bad_password}       -> {error, bad_password};
        {atomic, not_found}          -> {error, not_found};
        {atomic, {hash_failed, Why}} -> {error, {hash_failed, Why}};
        {aborted, R}                 -> {error, {mnesia, R}}
    end;

verify_user(_, _) -> {error, invalid}.

signup(F, L, E, U, P) when
      is_binary(F), byte_size(F) > 0,
      is_binary(L), byte_size(L) > 0,
      is_binary(E), byte_size(E) > 0,
      is_binary(U), byte_size(U) > 0,
      is_binary(P), byte_size(P) > 0 ->
    Fn = fun() ->
        Workfactor = 10,
        {ok, Salt} = bcrypt:gen_salt(Workfactor),
        {ok, Hash} = bcrypt:hashpw(P, Salt),
        case mnesia:read(user, U, write) of
            [] ->
                Id = erlang:unique_integer([monotonic, positive]),
                ok = mnesia:write(#user{
                    username       = U,
                    id             = Id,
                    firstname      = F,
                    lastname       = L,
                    email          = E,
                    password_hash  = Hash,
                    salt           = Salt
                }),
                Token = user_session:issue_token(U),
                {ok, Token};                      %% <— RETURN TOKEN
            _ ->
                mnesia:abort({username_taken, U})
        end
    end,
    case mnesia:transaction(Fn) of
        {atomic, {ok, Token}}          -> Token;
        {aborted, {username_taken, _}} -> {error, username_taken};
        {aborted, R}                   -> {error, {mnesia, R}}
    end.

