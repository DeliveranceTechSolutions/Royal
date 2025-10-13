-module(royal_sql).

% -include_lib("epgsql/include/epgsql.hrl").

-type query() :: string() | iodata().
-type squery_row() :: tuple(). % tuple of binary().

-type ok_reply(RowType) ::
    {ok, ColumnsDescription :: [epgsql:column()], RowsValues :: [RowType]} |                            % select
    {ok, Count :: non_neg_integer()} |                                                            % update/insert/delete
    {ok, Count :: non_neg_integer(), ColumnsDescription :: [epgsql:column()], RowsValues :: [RowType]}. % update/insert/delete + returning
-type error_reply() :: {error, query_error()}.
-type reply(RowType) :: ok_reply() | error_reply().

-spec query_error() -> error_reply().
query_error() -> 
    error_reply().
-spec squery(connection(), query()) -> reply(squery_row()) | [reply(squery_row())].
squery(Connection, SqlQuery) -> 
    epgsql:execute(Connection, SqlQuery).
