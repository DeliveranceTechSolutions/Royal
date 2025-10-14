%% royal_sql.erl
-module(royal_sql).
-export([squery/2]).

%% Pull epgsql types/records (e.g., #column{})
-include_lib("epgsql/include/epgsql.hrl").

%% -------- Types (no functions with same names) --------
-type query()      :: iodata().
-type row()        :: tuple().

-type ok_reply() ::
      {ok, non_neg_integer()}                                   %% write ops
    | {ok, [#column{}], [row()]}.                               %% SELECT

-type error_reply() :: {error, term()}.
-type reply()       :: ok_reply() | error_reply().

-spec squery(epgsql:connection(), query()) -> reply().
squery(Conn, Sql) ->
    %% For simple SQL strings, squery/2 is fine. Use execute/2+ prepared
    %% statements when you need parameters/binary formats.
    epgsql:squery(Conn, Sql).

