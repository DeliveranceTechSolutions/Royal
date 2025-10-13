-module(json_handler).
-behavior(cowboy_handler).

-export([init/2]).

init(Req0, State) ->
    Doc = {[{foo, [<<"bing">>, 2.3, true]}]},
    Req = cowboy_req:reply(200,
        #{<<"content-type">> => <<"application/json">>},
        jiffy:encode(Doc),
        Req0),
    {ok, Req, State}.
