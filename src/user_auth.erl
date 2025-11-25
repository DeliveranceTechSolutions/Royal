-module(user_auth).
-export([signup/5, verify_credentials/2]).

-include_lib("stdlib/include/qlc.hrl").

-record(user, {username, id, firstname, lastname, email, password_hash, salt}).


verify_credentials(U, P) ->
    verify_user(U, P).

verify_user(U, P) when
      is_binary(U), byte_size(U) > 0,
      is_binary(P), byte_size(P) > 0 ->
    %% Do DB work inside the TX; issue token after commit
    F = fun() ->
            case mnesia:read(user, U, read) of
                [#user{password_hash = StoredHash} = Rec] ->
                    case bcrypt:hashpw(P, StoredHash) of
                        {ok, Hash} when Hash =:= StoredHash -> {ok, Rec};
                        {ok, _}                             -> bad_password;
                        {error, Why}                        -> {hash_failed, Why}
                    end;
                [] -> 
                    not_found
            end
        end,
    case mnesia:transaction(F) of
        {atomic, {ok, Rec}} ->
            case user_session:issue_tokens(U, <<"web">>) of
              {ok, Tok, Ref}          -> {ok, Tok, Ref, user_handler:user_public(Rec)};   %% Tok is a binary
              {error, Reason, _}    -> {error, {token_issue_failed, Reason}}
            end;
        {atomic, bad_password} ->
            {error, bad_password};
        {atomic, not_found} ->
            {error, not_found};
        {aborted, R} ->
            {error, {mnesia, R}}
    end;

verify_user(_, _) -> {error, invalid}.

signup(F, L, E, U, P) when
      is_binary(F), byte_size(F) > 0,
      is_binary(L), byte_size(L) > 0,
      is_binary(E), byte_size(E) > 0,
      is_binary(U), byte_size(U) > 0,
      is_binary(P), byte_size(P) > 0 ->
    erlang:display("signup"),
    Fn = fun() ->
        Workfactor = 10,
        {ok, Salt} = bcrypt:gen_salt(Workfactor),
        {ok, Hash} = bcrypt:hashpw(P, Salt),
        erlang:display("signup Fn"),
        case mnesia:read(user, U, read) of
            [] ->
                Id = erlang:unique_integer([monotonic, positive]),
                UserRec = #user{
                    username      = U,
                    id            = Id,
                    firstname     = F,
                    lastname      = L,
                    email         = E,
                    password_hash = Hash,
                    salt          = Salt
                },

                ok = mnesia:write(user, UserRec, write),

                {ok, Access, Refresh} = user_session:issue_tokens(U, <<"web">>),
                {ok, Access, Refresh, user_handler:user_public(UserRec)};

            _ ->
                mnesia:abort({username_taken, U})
        end
    end,
    case mnesia:transaction(Fn) of
        {atomic, {ok, Token, Refresh, PublicUser}} -> {ok, Token, Refresh, PublicUser};
        {aborted, {username_taken, _}} -> {error, username_taken};
        {aborted, R}                   -> {error, {mnesia, R}}
    end.

