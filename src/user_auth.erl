-module(user_auth).
-behavior(gen_server).
-export([verify_credentials/2]).
-export([init/1, start_link/0, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) -> {ok, #{}}.

handle_call({verify_credentials, #{<<"username">> := U, <<"password">> := P}}, _From, St) ->
    Reply = verify_credentials(U,P),                     % fast, no blocking
    {reply, Reply, St};

handle_call({verify_credentials, _}, _From, St) ->
    {reply, {error, missing_fields}, St}.

handle_cast(_, St) -> {noreply, St}.
handle_info(_, St) -> {noreply, St}.
terminate(_, _) -> ok.
code_change(_, St, _) -> {ok, St}.

verify_credentials(U, P) ->
    verify_user(U, P).

verify_user(<<"kirk">>, <<"pass">>) -> ok;
verify_user(_, _)                  -> {error, invalid}.
