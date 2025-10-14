-module(royal_pool).
-behavior(supervisor).

-export([squery/2, equery/3]).
-export([init/1, start_link/0, stop/1]).
%-type query()      :: iodata().
%-type row()        :: tuple().
%
%-type ok_reply() ::
%      {ok, non_neg_integer()}                                   %% write ops
%    | {ok, [#column{}], [row()]}.                               %% SELECT
%
%-type error_reply() :: {error, term()}.
%-type reply()       :: ok_reply() | error_reply().

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

stop(_State) ->
    ok.

init([]) ->
    {ok, Pools} = application:get_env(royal, pools),
    PoolSpecs = lists:map(fun({Name, SizeArgs, WorkerArgs}) ->
        PoolArgs = [{name, {local, Name}},
            		{worker_module, royal_pool_worker}] ++ SizeArgs,
        poolboy:child_spec(Name, PoolArgs, WorkerArgs)
    end, Pools),
    {ok, {{one_for_one, 10, 10}, PoolSpecs}}.

squery(PoolName, Sql) ->
    poolboy:transaction(PoolName, fun(Worker) ->
        gen_server:call(Worker, {squery, Sql})
    end).

equery(PoolName, Stmt, Params) ->
    poolboy:transaction(PoolName, fun(Worker) ->
        gen_server:call(Worker, {equery, Stmt, Params})
    end).
