-module(royal_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
	supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Sup = #{strategy => one_for_one, intensity => 10, period => 10},
    Children = [
      #{
        id => auction_reg,
        start => {auction_reg, start_link, []},
        restart => permanent, shutdown => 5000, type => worker,
        modules => [auction_reg]
      },
      #{
        id => auction_srv,
        start => {auction_srv, start_link, []},
        restart => permanent, shutdown => 5000, type => worker,
        modules => [auction_srv]
      }
    ],
    {ok, {Sup, Children}}.
