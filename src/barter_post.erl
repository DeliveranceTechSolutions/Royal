-module(barter_post).
-behavior(gen_server).

%% Public API
-export([
    start_link/0,
    stop/0,
    reset/0,
    incr/0, incr/1,
    get/0, set/1
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-include_lib("kernel/include/logger.hrl").
-define(SERVER, ?MODULE).

-record(state, {
    author = <<"">> :: binary(),
    description = <<"">> :: binary(),
    default_price = 0 :: non_neg_integer(),
    user_price = 0 :: non_neg_integer(),
    current_loc = 
    count = 0 :: non_neg_integer()
}).

%%--------------------------------------------------------------------
%% Public API
%%--------------------------------------------------------------------

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec stop() -> ok.
stop() ->
    gen_server:call(?SERVER, stop).

-spec reset() -> ok.
reset() ->
    gen_server:cast(?SERVER, reset).

-spec incr() -> non_neg_integer().
incr() ->
    gen_server:call(?SERVER, {incr, 1}).

-spec incr(pos_integer()) -> non_neg_integer().
incr(N) when is_integer(N), N > 0 ->
    gen_server:call(?SERVER, {incr, N}).

-spec get() -> non_neg_integer().
get() ->
    gen_server:call(?SERVER, get).

-spec set(non_neg_integer()) -> ok.
set(N) when is_integer(N), N >= 0 ->
    gen_server:call(?SERVER, {set, N}).

%%--------------------------------------------------------------------
%% gen_server callbacks
%%--------------------------------------------------------------------

-spec init(list()) -> {ok, #state{}}.
init(_Args) ->
    process_flag(trap_exit, true),
    %% Load initial state here (from env/app config, DB, etc.)
    {ok, #state{}}.

-spec handle_call(term(), {pid(), term()}, #state{}) ->
    {reply, term(), #state{}} | {noreply, #state{}} | {stop, term(), term(), #state{}}.
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call(get, _From, State = #state{count = C}) ->
    {reply, C, State};

handle_call({set, N}, _From, _State) when is_integer(N), N >= 0 ->
    {reply, ok, #state{count = N}};

handle_call({incr, N}, _From, State = #state{count = C}) when is_integer(N), N > 0 ->
    NewC = C + N,
    {reply, NewC, State#state{count = NewC}};

handle_call(Unknown, _From, State) ->
    ?LOG_WARNING("Unknown call: ~p", [Unknown]),
    {reply, {error, unknown_call}, State}.

-spec handle_cast(term(), #state{}) ->
    {noreply, #state{}} | {stop, term(), #state{}}.
handle_cast(reset, _State) ->
    {noreply, #state{count = 0}};
handle_cast(Unknown, State) ->
    ?LOG_WARNING("Unknown cast: ~p", [Unknown]),
    {noreply, State}.

-spec handle_info(term(), #state{}) ->
    {noreply, #state{}} | {stop, term(), #state{}}.
handle_info({'EXIT', _Pid, Reason}, State) ->
    ?LOG_WARNING("Linked process died: ~p", [Reason]),
    {noreply, State};
handle_info(Info, State) ->
    ?LOG_DEBUG("Info: ~p", [Info]),
    {noreply, State}.

-spec terminate(term(), #state{}) -> ok.
terminate(Reason, _State) ->
    ?LOG_INFO("Shutting down ~p with reason: ~p", [?MODULE, Reason]),
    ok.

-spec code_change(term(), #state{}, term()) -> {ok, #state{}}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
