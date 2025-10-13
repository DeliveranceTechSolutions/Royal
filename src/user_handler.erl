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

handle_register(RegistrationForm) ->
    State = "Here",
    {ok, RegistrationForm, State}.

handle_login(Req0) -> 
    {ok,BodyBin,_} = deserialize(Req0),
    Map = jiffy:decode(BodyBin, [return_maps]),
    case gen_server:call(user_auth, {verify_credentials, Map}, 2000) of
        ok       -> reply_200(Req0);
        {error, invalid}   -> reply_404(Req0);
        {error, missing_fields} -> reply_400(Req0)
    end.

deserialize(Req0) ->
    cowboy_req:read_body(Req0, #{length => 1_048_576}).

reply_200(Req0) ->
    Req = cowboy_req:reply(200,
                           #{<<"content-type">> => <<"text/plain">>},
                           <<"200 login successful!">>,
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

init(Req0, #{action := Action}) ->
    Method = cowboy_req:method(Req0),
    case {Action, Method} of
        {register,<<"POST">>} -> 
            handle_register(Req0);
        {login_with_options,<<"POST">>} ->
            handle_login(Req0);
        _ -> 
            reply_404(Req0)
    end.




