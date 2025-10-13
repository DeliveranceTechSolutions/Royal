-module(royal_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_Type, _Args) ->
    Dispatch = cowboy_router:compile([
        {'_', [
               {"/", hello_handler, []},
               {"/v1/users/register", user_handler, #{action => register}},
               {"/v1/users/login/options", user_handler, #{action => login_with_options}},
               {"/v1/users/login/complete", user_handler, #{action => login_complete}},
               {"/v1/users/refresh", user_handler, #{action => refresh}},
               {"/v1/users/devices", user_handler, #{action => devices}},
               {"/v1/users/devices/:device_id", user_handler, #{action => delete_devices}},
               {"/v1/users/suspend", user_handler, #{action => suspend}},
               {"/v1/users/me", user_handler, #{action => me}}
        ]}
    ]),
    PrivDir = code:priv_dir(royal),
    Cert    = filename:join([PrivDir, "tls", "royal-server.cert.pem"]),
    Key     = filename:join([PrivDir, "tls", "royal-server.key.pem"]),

    {ok, _} = cowboy:start_tls(my_https_listener,
        [
            {port, 8443},
            {certfile, Cert},
            {keyfile, Key}
        ],
        #{env => #{dispatch => Dispatch}} 
    ),
	royal_sup:start_link(),
    user_auth:start_link().

stop(_State) ->
	ok.
