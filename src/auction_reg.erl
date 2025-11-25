-module(auction_reg).
-behaviour(gen_server).

-export([start_link/0, whereis/1, register/2, unregister/1, route/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(TAB, auction_reg).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

whereis(AuctionId) ->
    case ets:lookup(?TAB, AuctionId) of
        [{_, Pid}] when is_pid(Pid) -> {ok, Pid};
        _ -> {error, not_found}
    end.

register(AuctionId, Pid) ->
    gen_server:call(?MODULE, {register, AuctionId, Pid}).

unregister(AuctionId) ->
    gen_server:call(?MODULE, {unregister, AuctionId}).

route(AuctionId, Msg) ->
    case whereis(AuctionId) of
        {ok, Pid} -> Pid ! Msg, ok;
        Error -> Error
    end.

init([]) ->
    Tab = ets:new(?TAB, [named_table, public, set,
                         {read_concurrency, true}, {write_concurrency, true}]),
    {ok, #{tab => Tab, by_ref => #{}}}.

handle_call({register, Id, Pid}, _From, S = #{tab := Tab, by_ref := ByRef0}) ->
    Ref = erlang:monitor(process, Pid),
    ets:insert(Tab, {Id, Pid}),
    ByRef = ByRef0#{Ref => Id},
    {reply, ok, S#{by_ref := ByRef}};

handle_call({unregister, Id}, _From, S = #{tab := Tab, by_ref := ByRef0}) ->
    case ets:lookup(Tab, Id) of
        [{_, Pid}] ->
            %% Find and demonitor the matching Ref (optional optimization)
            erlang:demonitor(erlang:monitor(process, Pid), [flush]),
            ets:delete(Tab, Id),
            {reply, ok, S};
        _ ->
            {reply, ok, S}
    end.

handle_info({'DOWN', Ref, process, _Pid, _Reason}, S = #{tab := Tab, by_ref := ByRef0}) ->
    case maps:take(Ref, ByRef0) of
        {Id, ByRef} ->
            ets:delete(Tab, Id),
            {noreply, S#{by_ref := ByRef}};
        error ->
            {noreply, S}
    end;
handle_info(_, S) -> {noreply, S}.

handle_cast(_, S) -> {noreply, S}.
terminate(_, _) -> ok.
code_change(_, S, _) -> {ok, S}.
