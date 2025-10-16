%%--------------------------------------------------------------------
%% royal_jwt.erl — tiny JWT helper built on JOSE (HS256)
%%--------------------------------------------------------------------
%% deps: jose (e.g., {jose, "1.11.5"})
%% usage:
%%   Secret = <<"super-secret-32b-min">>.
%%   {ok, Token} = royal_jwt:issue(<<"user-123">>, Secret,
%%                                 #{aud => <<"royal-api">>, ttl => 900}).
%%   royal_jwt:verify(Token, Secret, #{aud => <<"royal-api">>}).
%%--------------------------------------------------------------------
-module(royal_jwt).

-export([
    issue/3,                % (Sub, Secret, Opts) -> {ok, TokenBin} | {error, Reason}
    verify/4,               % (TokenBin, Secret, Opts) -> {ok, Claims} | {error, Reason}
    bearer/1,               % (TokenBin) -> <<"Bearer ...">>
    from_bearer/1,          % (HeaderValBin) -> {ok, TokenBin} | error
    timewarp_safe_now/0,                   % () -> integer seconds
    validate_claims/4
]).

-include_lib("kernel/include/logger.hrl").
-include_lib("jose/include/jose_jwt.hrl").

-type claims() :: map().
-type options() :: #{aud => binary(), iss => binary(), ttl => pos_integer(),
                     nbf_skew => non_neg_integer(), kid => binary()}.

%%--------------------------------------------------------------------
%% Public API
%%--------------------------------------------------------------------

-spec issue(binary(), binary(), options()) -> {ok, binary(), binary()} | {error, term()}.
issue(Sub, Secret, Opts) when is_binary(Sub), is_binary(Secret), is_map(Opts) ->
    try
        Iss = maps:get(iss, Opts, <<"royal">>),
        Aud = maps:get(aud, Opts, <<"royal-api">>),
        TTL = maps:get(ttl, Opts, 900),             % 15 minutes
        NbfSkew = maps:get(nbf_skew, Opts, 30),     % 30s clock skew
        Kid = maps:get(kid, Opts, kid_from_secret(Secret)),
        Now = timewarp_safe_now(),
        JWK = jwk_from_secret(Secret),
        Ref = new_random_token(64),
        %ok = mnesia:write(#session{
        %    user_id             = Id,
        %    token = Ref,
        %    expires_at = safe
        %}),

        royal_mnesia:create(session,  [id, user_id, token, expires_at]),
        Claims = #{
          <<"iss">> => Iss,
          <<"sub">> => Sub,
          <<"aud">> => Aud,
          <<"iat">> => Now,
          <<"nbf">> => Now - NbfSkew,
          <<"exp">> => Now + TTL
        },
        JWS = #{<<"alg">> => <<"HS256">>, <<"typ">> => <<"JWT">>, <<"kid">> => Kid},
        
        {_Hdr1, Signed} = jose_jwt:sign(JWK, JWS, Claims),
        {_Hdr2, Compact} = jose_jws:compact(Signed),
        {ok, Compact, Ref}
    catch
        Class:Reason:Stack ->
            ?LOG_ERROR("JWT issue error ~p:~p ~p", [Class, Reason, Stack]),
            {error, issue_failed}
    end.

-spec verify(binary(), binary(), binary(), options()) -> {ok, claims()} | {error, term()}.
verify(Token, Refresh, Secret, Opts) when is_binary(Token), is_binary(Secret), is_map(Opts) ->
    try
        Iss = maps:get(iss, Opts, <<"royal">>),
        Aud = maps:get(aud, Opts, <<"royal-api">>),
        Skew = maps:get(nbf_skew, Opts, 30),
        JWK = jwk_from_secret(Secret),

        case jose_jwt:verify_strict(JWK, [<<"HS256">>], Token) of
            {true, #jose_jwt{fields = Claims}, _JWS} ->
                case validate_claims(Claims, Iss, Aud, Skew) of
                    ok      -> {ok, Claims};
                    {error, _}=E -> E
                end;
            _ ->
                {error, bad_signature}
        end
    catch
        Class:Reason:Stack ->
            ?LOG_WARNING("JWT verify crash ~p:~p ~p", [Class, Reason, Stack]),
            {error, verify_failed}
    end.

-spec bearer(binary()) -> binary().
bearer(Token) when is_binary(Token) ->
    << "Bearer ", Token/binary >>.

-spec from_bearer(binary()) -> {ok, binary()} | error.
from_bearer(<<"Bearer ", Rest/binary>>) when byte_size(Rest) > 0 -> {ok, Rest};
from_bearer(_) -> error.

-spec timewarp_safe_now() -> integer().
timewarp_safe_now() -> erlang:system_time(second).

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

-spec jwk_from_secret(binary()) -> map().
jwk_from_secret(Secret) ->
    #{
      <<"kty">> => <<"oct">>,
      <<"k">>   => jose_base64url:encode(Secret)
    }.

-spec kid_from_secret(binary()) -> binary().
kid_from_secret(Secret) ->
    %% kid = base64url(sha256(secret)) — deterministic, no PII
    <<Hash:256>> = crypto:hash(sha256, Secret),
    jose_base64url:encode(<<Hash:256>>).

-spec validate_claims(map(), binary(), binary(), non_neg_integer())
      -> ok | {error, term()}.
validate_claims(Claims, Iss, Aud, Skew) ->
    Now = timewarp_safe_now(),
    Exp = maps:get(<<"exp">>, Claims, 0),
    Nbf = maps:get(<<"nbf">>, Claims, 0),
    CIss = maps:get(<<"iss">>, Claims, <<>>),
    CAud = maps:get(<<"aud">>, Claims, <<>>),
    case true of
        _ when not is_integer(Exp); Exp =< 0 ->
            {error, bad_exp};
        _ when Now > Exp ->
            {error, expired};
        _ when not is_integer(Nbf) ->
            {error, bad_nbf};
        _ when Now < (Nbf - Skew) ->
            {error, not_before};
        _ when CIss =/= Iss ->
            {error, bad_issuer};
        _ when CAud =/= Aud ->
            {error, bad_audience};
        true ->
            ok
    end.

b64url(Bin) ->
    Bin1 = base64:encode(Bin),
    Bin2 = binary:replace(Bin1, <<"+">>, <<"-">>, [global]),
    Bin3 = binary:replace(Bin2, <<"/">>, <<"_">>, [global]),
    binary:replace(Bin3, <<"=">>, <<>>, [global]).

new_random_token(NumBytes) ->
    b64url(crypto:strong_rand_bytes(NumBytes)).

sha256(Bin) -> crypto:hash(sha256, Bin).
now_s() -> erlang:system_time(second).

