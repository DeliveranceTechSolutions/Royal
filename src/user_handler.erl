-module(user_handler).
-behavior(cowboy_handler).

-export([init/2, handle_register/1]).

%%-spec handle_login(LoginOptions) -> Response.
%%-spec handle_login(LoginOption, Completion) -> Response.
%%-spec handle_refresh(AccessToken, RefreshToken) -> AccessToken.
%%-spec handle_devices(DeviceID) -> Response.
%%-spec handle_device_delete(DeviceID) -> Response.
%%-spec handle_suspend(DeviceID) -> Response.
%%-spec handle_me(UserID) -> Profile.

reply_200(Req0) ->
    Req = cowboy_req:reply(200,
                           #{<<"content-type">> => <<"text/plain">>},
                           <<"200 login successful!">>,
                           Req0),
    State = nil,
    {ok, Req, State}.

reply_200_login(Req0, Token) ->
    Req = cowboy_req:reply(200,
                           #{<<"content-type">> => <<"text/plain">>},
                            Token, 
                            Req0),
    State = nil,
    {ok, Req, State}.

reply_307(Req0) ->
    Req = cowboy_req:reply(307,
                           #{<<"content-type">> => <<"text/plain">>},
                           <<"307 redirect successful!">>,
                           Req0),
    State = nil,
    {ok, Req, State}.

reply_400(Req0) ->
    Req = cowboy_req:reply(404,
                           #{<<"content-type">> => <<"text/plain">>},
                           <<"400 not found!">>,
                           Req0),
    State = nil,
    {ok, Req, State}.

reply_404(Req0) ->
    Req = cowboy_req:reply(404,
                           #{<<"content-type">> => <<"text/plain">>},
                           <<"404 not found!">>,
                           Req0),
    State = nil,
    {ok, Req, State}.

handle_register(RegistrationForm) ->
    State = "Here",
    {ok, RegistrationForm, State}.

handle_login(Req0) -> 
    {ok,BodyBin,_} = deserialize(Req0),
    Map = jiffy:decode(BodyBin, [return_maps]),
    case user_auth:verify_credentials(
           maps:get(<<"username">>, Map),
           maps:get(<<"password">>, Map)
    ) of
        {ok, Token} -> reply_200_login(Req0, Token);
        {error, invalid}   -> reply_404(Req0);
        {error, missing_fields} -> reply_400(Req0)
    end.

handle_refresh(Req0) ->
    {ok,BodyBin,_} = deserialize(Req0),
    Map = jiffy:decode(BodyBin, [return_maps]),
    case user_session:refresh_tokens(
           maps:get(<<"access_token">>, Map),
           maps:get(<<"refresh_token">>, Map)
    ) of
        ok       -> reply_200(Req0);
        {error, invalid}   -> reply_404(Req0);
        {error, missing_fields} -> reply_400(Req0)
    end.

handle_devices(Req0) ->
    {ok,BodyBin,_} = deserialize(Req0),
    Map = jiffy:decode(BodyBin, [return_maps]),
    case user_auth:verify_credentials(
           maps:get(<<"username">>, Map),
           maps:get(<<"password">>, Map)
    ) of
        ok       -> reply_200(Req0);
        {error, invalid}   -> reply_404(Req0);
        {error, missing_fields} -> reply_400(Req0)
    end.
handle_delete_devices(Req0) ->
    {ok,BodyBin,_} = deserialize(Req0),
    Map = jiffy:decode(BodyBin, [return_maps]),
    case user_auth:verify_credentials(
           maps:get(<<"username">>, Map),
           maps:get(<<"password">>, Map)
    ) of
        ok       -> reply_200(Req0);
        {error, invalid}   -> reply_404(Req0);
        {error, missing_fields} -> reply_400(Req0)
    end.
handle_suspend(Req0) ->
    {ok,BodyBin,_} = deserialize(Req0),
    Map = jiffy:decode(BodyBin, [return_maps]),
    case user_auth:verify_credentials(
           maps:get(<<"username">>, Map),
           maps:get(<<"password">>, Map)
    ) of
        ok       -> reply_200(Req0);
        {error, invalid}   -> reply_404(Req0);
        {error, missing_fields} -> reply_400(Req0)
    end.

handle_dashboard(Req0) ->
    {ok,BodyBin,_} = deserialize(Req0),
    Map = jiffy:decode(BodyBin, [return_maps]),
    case user_auth:verify_credentials(
           maps:get(<<"username">>, Map),
           maps:get(<<"password">>, Map)
    ) of
        ok       -> reply_307(Req0);
        {error, invalid}   -> reply_404(Req0);
        {error, missing_fields} -> reply_400(Req0)
    end.
    
handle_me(Req0) ->
    {ok,BodyBin,_} = deserialize(Req0),
    Map = jiffy:decode(BodyBin, [return_maps]),
    case user_auth:verify_credentials(
           maps:get(<<"username">>, Map),
           maps:get(<<"password">>, Map)
    ) of
        ok       -> reply_200(Req0);
        {error, invalid}   -> reply_404(Req0);
        {error, missing_fields} -> reply_400(Req0)
    end.

deserialize(Req0) ->
    cowboy_req:read_body(Req0, #{length => 1_048_576}).


init(Req0, #{action := Action}) ->
    Method = cowboy_req:method(Req0),
    case {Action, Method} of
        {register,<<"POST">>} -> 
            handle_register(Req0);
        {login_with_options,<<"POST">>} ->
            handle_login(Req0);
        {refresh_tokens,<<"POST">>} ->
            handle_refresh(Req0);
        {devies,<<"POST">>} ->
            handle_devices(Req0);
        {delete_devices,<<"POST">>} ->
            handle_delete_devices(Req0);
        {suspend,<<"POST">>} ->
            handle_suspend(Req0);
        {dashboard,<<"POST">>} ->
            handle_dashboard(Req0);
        {me,<<"POST">>} ->
            handle_me(Req0);
        _ -> 
            reply_404(Req0)
    end.




