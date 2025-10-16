-module(user_handler).
-behaviour(cowboy_handler).

-export([init/2, user_public/1]).

-define(JSON_CT, #{<<"content-type">> => <<"application/json">>}).

%% ===== helpers =====

-spec read_json(cowboy_req:req()) ->
        {{ok, map()} | {error, bad_json} | no_body, cowboy_req:req()}.
read_json(Req0) ->
    case cowboy_req:has_body(Req0) of
        false -> {no_body, Req0};
        true  ->
            {ok, BodyBin, Req1} = cowboy_req:read_body(Req0, #{length => 1048576}),
            case catch jiffy:decode(BodyBin, [return_maps]) of
                Map when is_map(Map) -> {{ok, Map}, Req1};
                _                    -> {{error, bad_json}, Req1}
            end
    end.

reply_json(Req0, Status, Map) ->
    Body = jiffy:encode(Map),
    cowboy_req:reply(Status, ?JSON_CT, Body, Req0).

user_public({user, U, Id, F, L, E, _Hash, _Salt}) ->
    #{
      <<"username">>  => U,
      <<"id">>        => Id,
      <<"firstname">> => F,
      <<"lastname">>  => L,
      <<"email">>     => E
    }.

%% Auth that DOES NOT read the body; it uses the map we already parsed.
authenticate_api_call(Map) ->
    %% Adjust as needed: ideally look at Authorization header instead of body.
    Required = [<<"access_token">>, <<"refresh_token">>, <<"user">>],
    case [K || K <- Required, not maps:is_key(K, Map)] of
        [] ->
            Token   = maps:get(<<"access_token">>, Map),
            Refresh = maps:get(<<"refresh_token">>, Map),
            case user_session:authenticate_user(Token, Refresh) of
                ok    -> ok;
                error -> error
            end;
        _Missing ->
            missing_fields
    end.

%% ===== action handlers (take already-parsed Map) =====

handle_login(Req0, M) ->
    case {maps:find(<<"username">>, M), maps:find(<<"password">>, M)} of
        {{ok, U}, {ok, P}} ->
            case user_auth:verify_credentials(U, P) of
                {ok, Token, Refresh, User} ->
                    Req1 = reply_json(Req0, 200, #{
                        <<"access_token">> => Token,
                        <<"refresh_token">> => Refresh,
                        <<"user">>         => User
                    }),
                    {ok, Req1, undefined};
                {error, not_found} ->
                    {ok, reply_json(Req0, 401, #{
                        <<"error">> => #{<<"code">> => <<"invalid_credentials">>,
                                         <<"message">> => <<"Invalid login">>}
                    }), undefined};
                {error, bad_password} ->
                    {ok, reply_json(Req0, 401, #{
                        <<"error">> => #{<<"code">> => <<"invalid_credentials">>,
                                         <<"message">> => <<"Invalid login">>}
                    }), undefined};
                {error, _} ->
                    {ok, reply_json(Req0, 500, #{
                        <<"error">> => #{<<"code">> => <<"auth_error">>,
                                         <<"message">> => <<"Authentication error">>}
                    }), undefined}
            end;
        _ ->
            {ok, reply_json(Req0, 400, #{
                <<"error">> => #{<<"code">> => <<"missing_fields">>,
                                 <<"message">> => <<"username and password required">>}
            }), undefined}
    end.

handle_signup(Req0, M) ->
    Required = [<<"firstname">>, <<"lastname">>, <<"email">>, <<"username">>, <<"password">>],
    case [K || K <- Required, not maps:is_key(K, M)] of
        [] ->
            F = maps:get(<<"firstname">>, M),
            L = maps:get(<<"lastname">>, M),
            E = maps:get(<<"email">>, M),
            U = maps:get(<<"username">>, M),
            P = maps:get(<<"password">>, M),
            case user_auth:signup(F, L, E, U, P) of
                {ok, Token, PublicUser} ->
                    {ok, reply_json(Req0, 201, #{
                        <<"access_token">> => Token,
                        <<"user">>         => PublicUser
                    }), undefined};
                {error, username_taken} ->
                    {ok, reply_json(Req0, 409, #{
                        <<"error">> => #{<<"code">> => <<"username_taken">>,
                                         <<"message">> => <<"Username already exists">>}
                    }), undefined};
                {error, {mnesia, _}} ->
                    {ok, reply_json(Req0, 500, #{
                        <<"error">> => #{<<"code">> => <<"db_error">>,
                                         <<"message">> => <<"Database error">>}
                    }), undefined};
                {error, _} ->
                    {ok, reply_json(Req0, 400, #{
                        <<"error">> => #{<<"code">> => <<"signup_failed">>,
                                         <<"message">> => <<"Unable to sign up">>}
                    }), undefined}
            end;
        Missing ->
            {ok, reply_json(Req0, 400, #{
                <<"error">> => #{<<"code">> => <<"missing_fields">>, <<"missing">> => Missing}
            }), undefined}
    end.

handle_barter_post(Req0, M) ->
    Required = [<<"title">>, <<"details">>, <<"author">>, <<"location">>],
    case [K || K <- Required, not maps:is_key(K, M)] of
        [] ->
            F = maps:get(<<"firstname">>, M),
            L = maps:get(<<"lastname">>, M),
            E = maps:get(<<"email">>, M),
            U = maps:get(<<"username">>, M),
            P = maps:get(<<"password">>, M),
            case user_auth:signup(F, L, E, U, P) of
                {ok, Token, PublicUser} ->
                    {ok, reply_json(Req0, 201, #{
                        <<"access_token">> => Token,
                        <<"user">>         => PublicUser
                    }), undefined};
                {error, username_taken} ->
                    {ok, reply_json(Req0, 409, #{
                        <<"error">> => #{<<"code">> => <<"username_taken">>,
                                         <<"message">> => <<"Username already exists">>}
                    }), undefined};
                {error, {mnesia, _}} ->
                    {ok, reply_json(Req0, 500, #{
                        <<"error">> => #{<<"code">> => <<"db_error">>,
                                         <<"message">> => <<"Database error">>}
                    }), undefined};
                {error, _} ->
                    {ok, reply_json(Req0, 400, #{
                        <<"error">> => #{<<"code">> => <<"signup_failed">>,
                                         <<"message">> => <<"Unable to sign up">>}
                    }), undefined}
            end;
        Missing ->
            {ok, reply_json(Req0, 400, #{
                <<"error">> => #{<<"code">> => <<"missing_fields">>, <<"missing">> => Missing}
            }), undefined}
    end.

not_implemented(Req0) ->
    {ok, reply_json(Req0, 501, #{
        <<"error">> => #{<<"code">> => <<"not_implemented">>}
    }), undefined}.

handle_404(Req0) ->
    {ok, reply_json(Req0, 404, #{
        <<"error">> => #{<<"code">> => <<"not_found">>, <<"message">> => <<"Route not found">>}
    }), undefined}.

%% ===== cowboy entrypoint =====

init(Req0, #{action := Action}) ->
    Method = cowboy_req:method(Req0),
    %% Read body ONCE (or no_body for GET/etc.)
    {BodyRes, Req1} =
        case Method of
            <<"GET">> -> {no_body, Req0};
            _         -> read_json(Req0)
        end,

    %% Decide if this route needs auth
    NeedsAuth =
        case Action of
            login_with_options -> false;
            signup             -> false;
            _                  -> true
        end,

    %% Gate on bad JSON early for routes that expect a body
    case {Method, BodyRes} of
        {<<"POST">>, {error, bad_json}} ->
            {ok, reply_json(Req1, 400, #{
                <<"error">> => #{<<"code">> => <<"bad_json">>,
                                 <<"message">> => <<"Invalid JSON body">>}
            }), undefined};
        _Else ->
            ok
    end,

    %% Route
    case {Action, Method, BodyRes, NeedsAuth} of
        %% Public routes (no auth)
        {login_with_options, <<"POST">>, {ok, M}, false} -> handle_login(Req1, M);
        {signup,              <<"POST">>, {ok, M}, false} -> handle_signup(Req1, M);

        %% Protected routes (auth first)
        {_Any, <<"POST">>, {ok, M}, true} ->
            case authenticate_api_call(M) of
                ok              -> 
                 case {Action, Method} of
                    {barter_post,    <<"POST">>}    ->  barter_post(Req1);
                    {refresh_tokens, <<"POST">>}    ->  not_implemented(Req1);
                    {devices,        <<"POST">>}    ->  not_implemented(Req1);
                    {delete_devices, <<"POST">>}    ->  not_implemented(Req1);
                    {suspend,        <<"POST">>}    ->  not_implemented(Req1);
                    {dashboard,      <<"POST">>}    ->  not_implemented(Req1);
                    {me,             <<"POST">>}    ->  not_implemented(Req1);
                    _                               ->  not_implemented(Req1)
                end;
                missing_fields  -> {ok, reply_json(Req1, 400, #{
                                        <<"error">> => #{<<"code">> => <<"missing_fields">>,
                                                         <<"message">> => <<"Missing fields in request">>}
                                    }), undefined};
                error           -> {ok, reply_json(Req1, 401, #{
                                        <<"error">> => #{<<"code">> => <<"unauthorized">>,
                                                         <<"message">> => <<"Bad or expired tokens">>}
                                    }), undefined}
            end;
        %% Fallbacks
        _ -> handle_404(Req1)
    end.

    

