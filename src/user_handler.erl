-module(user_handler).
-behaviour(cowboy_handler).

-export([init/2]).

-define(JSON_CT, #{<<"content-type">> => <<"application/json">>}).

-record(user, {username, id, firstname, lastname, email, password_hash}).
%% ===== helpers =====

-spec read_json(cowboy_req:req()) -> {ok, map(), cowboy_req:req()} | {error, bad_json, cowboy_req:req()}.
read_json(Req0) ->
    {ok, BodyBin, Req1} = cowboy_req:read_body(Req0, #{length => 1048576}),
    try jiffy:decode(BodyBin, [return_maps]) of
        Map when is_map(Map) -> {ok, Map, Req1}
    catch _:_ -> {error, bad_json, Req1}
    end.

reply_json(Req0, Status, Map) ->
    erlang:display(Map),
    Body = jiffy:encode(Map),
    cowboy_req:reply(Status, ?JSON_CT, Body, Req0).

user_public(#user{username = U, id = Id, firstname = F, lastname = L, email = E}) ->
    #{username => U, id => Id, firstname => F, lastname => L, email => E}.

%% ===== per-action handlers =====

handle_login(Req0) ->
    case read_json(Req0) of
        {ok, M, Req1} ->
            case {maps:find(<<"username">>, M), maps:find(<<"password">>, M)} of
                { {ok, U}, {ok, P} } ->
                    case user_auth:verify_credentials(U, P) of
                        {ok, Token} ->
                            reply_json(Req1, 200, Token);
                        {error, not_found} ->
                            reply_json(Req1, 401, #{error => #{code => <<"invalid_credentials">>, message => <<"Invalid login">>}});
                        {error, bad_password} ->
                            reply_json(Req1, 401, #{error => #{code => <<"invalid_credentials">>, message => <<"Invalid login">>}});
                        {error, _} ->
                            reply_json(Req1, 500, #{error => #{code => <<"auth_error">>, message => <<"Authentication error">>}})
                    end;
                _ ->
                    reply_json(Req1, 400, #{error => #{code => <<"missing_fields">>, message => <<"username and password required">>}})
            end;
        {error, bad_json, Req1} ->
            reply_json(Req1, 400, #{error => #{code => <<"bad_json">>, message => <<"Invalid JSON body">>}})
    end.

handle_signup(Req0) ->
    case read_json(Req0) of
        {ok, M, Req1} ->
            Required = [<<"firstname">>, <<"lastname">>, <<"email">>, <<"username">>, <<"password">>],
            case [K || K <- Required, not maps:is_key(K, M)] of
                [] ->
                    case user_auth:signup(
                           maps:get(<<"firstname">>, M),
                           maps:get(<<"lastname">>, M),
                           maps:get(<<"email">>, M),
                           maps:get(<<"username">>, M),
                           maps:get(<<"password">>, M)
                    ) of
                        {ok, Token} ->
                            reply_json(Req1, 201, Token);
                        {error, username_taken} ->
                            reply_json(Req1, 409, #{error => #{code => <<"username_taken">>, message => <<"Username already exists">>}});
                        {error, {mnesia, _}} ->
                            reply_json(Req1, 500, #{error => #{code => <<"db_error">>, message => <<"Database error">>}});
                        {error, _} ->
                            reply_json(Req1, 400, #{error => #{code => <<"signup_failed">>, message => <<"Unable to sign up">>}})
                    end;
                Missing ->
                    reply_json(Req1, 400, #{error => #{code => <<"missing_fields">>, missing => Missing}})
            end;
        {error, bad_json, Req1} ->
            reply_json(Req1, 400, #{error => #{code => <<"bad_json">>, message => <<"Invalid JSON body">>}})
    end.

handle_404(Req0) ->
    reply_json(Req0, 404, #{error => #{code => <<"not_found">>, message => <<"Route not found">>}}).

%% ===== cowboy entrypoint =====

init(Req0, #{action := Action}) ->
    Method = cowboy_req:method(Req0),
    case {Action, Method} of
        {login_with_options, <<"POST">>} -> {ok, handle_login(Req0), undefined};
        {signup,              <<"POST">>} -> {ok, handle_signup(Req0), undefined};

        %% fix your other actions similarly; example stubs:
        {refresh_tokens, <<"POST">>}     -> {ok, reply_json(Req0, 501, #{error => #{code => <<"not_implemented">>}}), undefined};
        {devices,        <<"POST">>}     -> {ok, reply_json(Req0, 501, #{error => #{code => <<"not_implemented">>}}), undefined};
        {delete_devices, <<"POST">>}     -> {ok, reply_json(Req0, 501, #{error => #{code => <<"not_implemented">>}}), undefined};
        {suspend,        <<"POST">>}     -> {ok, reply_json(Req0, 501, #{error => #{code => <<"not_implemented">>}}), undefined};
        {dashboard,      <<"POST">>}     -> {ok, reply_json(Req0, 501, #{error => #{code => <<"not_implemented">>}}), undefined};
        {me,             <<"POST">>}     -> {ok, reply_json(Req0, 501, #{error => #{code => <<"not_implemented">>}}), undefined};
        _                                  -> {ok, handle_404(Req0), undefined}
    end.

