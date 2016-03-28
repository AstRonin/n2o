-module(n2o_fcgi).
-include_lib("n2o/include/wf.hrl").
-include_lib("stdlib/include/ms_transform.hrl").

%% API
-export([init/0, send/1, stop/0]).

-define(PROTO_CGI, <<"CGI/1.1">>).
-define(PROTO_HTTP, <<"HTTP/1.1">>).
-define(DEF_FCGI_PORT, 9000).
-define(DEF_RESP_STATUS, 200).

-define(URL_PARTS, (get(url_parts))).

-record(url_parts, {scheme, userInfo, host, port, path, query}).

%% ===========================================================
%% API
%% ===========================================================

init() ->
    case ex_fcgi:start(fcgi, wf:config(n2o_fcgi, address, localhost), wf:config(n2o_fcgi, port, ?DEF_FCGI_PORT)) of
        {ok, _Pid} -> ok;
        {error, {already_started, _Pid}} -> ok
    end.

stop() ->
    ex_fcgi:stop(fcgi).

-spec send(Params :: #http{}) -> binary().
send(Params) ->
    wf:state(status, 200),
    make_url_parts(Params),
    vhosts(),
    {Body, P1} = case bs(Params) of {ok, B, NewP} -> {B, NewP}; _ -> {<<>>, Params} end,
    FCGIParams = get_params(P1),

    {ok, Ref} = ex_fcgi:begin_request(fcgi, responder, FCGIParams, wf:config(n2o_fcgi, timeout, 60000)),
    case P1#http.has_body of
        true -> ex_fcgi:send(fcgi, Ref, Body);
        _ -> ok
    end,
    ex_fcgi:end_request(fcgi, Ref),

    Ret = ret(),
    RetH = wf:state(n2o_fcgi_response_headers),
    set_header_to_cowboy(RetH, byte_size(Ret)),
    terminate(),
    %% @todo Return headers from cgi because cowboy don't give access to resp_headers
    {Ret, wf:state(status), RetH}.

%% ===========================================================
%% Prepare Request
%% ===========================================================

vhosts() ->
    Vs = wf:config(n2o_fcgi, vhosts, []), vhosts(Vs).
vhosts([H|T]) ->
    S = proplists:get_value(server_name, H, ""),
    A = proplists:get_value(aliase, H, ""),
    case wf:to_list(host()) of
        Host when Host =:= S orelse Host =:= A ->
            wf:state(vhost, H), ok;
        _ ->
            vhosts(T)
    end;
vhosts([]) -> wf:state(vhost, []), ok.

vhost(Key, Def) ->
    proplists:get_value(Key, wf:state(vhost), Def).

-spec get_params(Params :: #http{}) -> term().
get_params(Params) ->
    {{PeerIP, PeerPort}, _} = cowboy_req:peer(?REQ),
    Method = method(Params),
    Port = port(),
    Path = path(),
    QS = qs(),

    Root = vhost(root, ""),
    DefScript = wf:to_binary(vhost(index, "index.php")),
    {FPath, FScript, FPathInfo} = final_path(Path, DefScript),

    %% @todo Waiting of https://github.com/ninenines/cowboy/issues/950
    %% HHttps = case HTTPS ? of <<"https">> -> [{<<"HTTPS">>, <<"'on'">>}]; _ -> [] end,
    HHttps = [],

    [{<<"GATEWAY_INTERFACE">>, ?PROTO_CGI},
        {<<"QUERY_STRING">>, QS},
        {<<"REMOTE_ADDR">>, wf:to_binary(inet:ntoa(PeerIP))},
        {<<"REMOTE_PORT">>, wf:to_binary(PeerPort)},
        {<<"REQUEST_METHOD">>, Method},
        {<<"REQUEST_URI">>, <<Path/binary, (case QS of <<>> -> <<>>; V -> <<"?", V/binary>> end)/binary>>},
        {<<"DOCUMENT_ROOT">>, wf:to_binary(Root)},
        {<<"SCRIPT_FILENAME">>, wf:to_binary([vhost(root, ""), FPath, "/", FScript])},
        {<<"SCRIPT_NAME">>, wf:to_binary(["/", FScript])},
        %% {<<"SERVER_ADDR">>, <<"">>}, % I don't now how cowboy return self ip
        {<<"SERVER_NAME">>, wf:to_binary(vhost(server_name, wf:config(n2o_fcgi, address, "")))},
        {<<"SERVER_PORT">>, wf:to_binary(Port)},
        {<<"SERVER_PROTOCOL">>, ?PROTO_HTTP},
        {<<"SERVER_SOFTWARE">>, <<"cowboy">>}] ++
        path_info_headers(Root, FPathInfo) ++
        HHttps ++
        http_headers(Params) ++
        post_headers(Params, Method).

make_url_parts(#http{url = Url}) ->
    case Url of
        undefined -> put(url_parts, #url_parts{});
        U ->
            case http_uri:parse(wf:to_list(U), [{scheme_defaults, [
                {http,80},{https,443},{ftp,21},{ssh,22},{sftp,22},{tftp,69},{ws,80},{wss,443}]}]) of
                {ok, {Scheme, UserInfo, Host, Port, Path, Query}} ->
                    R = #url_parts{scheme = Scheme, userInfo = UserInfo, host = Host, port = Port, path = Path, query = Query},
                    put(url_parts, R);
                {error, _Reason} ->
                    put(url_parts, #url_parts{})
            end
    end.

external_headers(#http{headers = Hs}) ->
    case Hs of undefined -> []; _ -> Hs end.
external_host_header() ->
    case ?URL_PARTS#url_parts.host of
        undefined -> undefined;
        Host ->
            Port = case ?URL_PARTS#url_parts.port of P when P =:= 80 orelse P =:= 443 -> ""; P1 -> ":" ++ wf:to_list(P1) end,
            {<<"host">>, wf:to_binary([Host, Port])}
    end.
external_ajax_header() ->
    case ?URL_PARTS#url_parts.host of
        undefined -> undefined;
        _ ->
            {<<"x-requested-with">>, <<"XMLHttpRequest">>}
    end.
post_headers(#http{has_body = Has, body_length = Len}, Method) ->
    case Has of
        true when Method =:= <<"POST">>; Method =:= <<"PUT">>; Method =:= <<"DELETE">> ->
            [{"CONTENT_TYPE", <<"application/x-www-form-urlencoded">>},
                {"CONTENT_LENGTH", wf:to_binary(Len)}];
        _ -> []
    end.
path_info_headers(Root, FPathInfo) ->
    case FPathInfo of
        [] -> [];
        _ -> [{<<"PATH_INFO">>, wf:to_binary(FPathInfo)},
            {<<"PATH_TRANSLATED">>, wf:to_binary([Root, FPathInfo])}]
    end.
host() ->
    case ?URL_PARTS#url_parts.host of
        undefined ->
            case cowboy_req:host_info(?REQ) of
                {undefined, _} -> {H , _} = cowboy_req:host(?REQ), H;
                {H , _} -> H
            end;
        V ->
            V end.
method(Params) ->
    case Params#http.method of undefined -> {M, _} = cowboy_req:method(?REQ), M; V -> wf:to_binary(string:to_upper(wf:to_list(V))) end.
port() ->
    case ?URL_PARTS#url_parts.port of undefined -> {Port , _} = cowboy_req:port(?REQ), Port; V -> V end.
path() ->
    case ?URL_PARTS#url_parts.path of undefined -> get_cowboy_path(); V -> wf:to_binary(V) end.
qs() ->
    case ?URL_PARTS#url_parts.query of undefined -> {Q, _} = cowboy_req:qs(?REQ), Q; V -> wf:to_binary(string:strip(V, left, $?)) end.
bs(#http{body = Body} = P) ->
    case Body of
        undefined ->
            case cowboy_req:has_body(?REQ) of
                true -> case cowboy_req:body(?REQ) of
                            {ok, CB, _} ->
                                P1 = P#http{has_body = true, body_length = byte_size(CB)},
                                {ok, CB, P1};
                            _ ->
                                {empty, <<>>, P}
                        end;
                _ ->
                    {empty, <<>>, P}
            end;
        E when E =:= <<>> orelse E =:= <<"">> orelse E =:= "" ->
            {empty, <<>>, P};
        B -> P2 = P#http{has_body = true, body_length = byte_size(B)},
            {ok, B, P2}
    end.

-spec http_headers(Params :: [tuple()]) -> [tuple()].
http_headers(Params) ->
    {H, _} = cowboy_req:headers(?REQ),
    H1 = case external_host_header() of undefined -> H; V -> lists:keystore(<<"host">>, 1, H, V) end,
    H2 = case external_ajax_header() of undefined -> H1; V1 -> lists:keystore(<<"x-requested-with">>, 1, H1, V1) end,
    H3 = H2 ++ external_headers(Params),
    http_headers(H3, []).
http_headers([H|T], New) ->
    K = element(1, H),
    K2 = "HTTP_" ++ string:to_upper(string:join(string:tokens(wf:to_list(K), "-"), "_")),
    http_headers(T, New ++ [{wf:to_binary(K2), element(2, H)}]);
http_headers([], New) ->
    New.

get_cowboy_path() ->
    case cowboy_req:path_info(?REQ) of
        {undefined, _} ->
            case cowboy_req:path(?REQ) of
                {undefined, _} -> <<"/">>;
                {P, _} -> P
            end;
        {P, _} -> <<"/", (binary_join(P, <<"/">>))/binary>>
    end.

final_path(CowboyPath, DefScript) ->
    {Path, Script, PathInfo} =
        case explode_path(CowboyPath) of
            {path, P} -> {P, DefScript, []};
            {path_parts, P, S, I} -> {P, S, I}
        end,
    {FPath, FScript} =
        case rewrite(Path ++ "/" ++ Script) of
            {true, P1} ->
                case explode_path(P1) of
                    {path, P2} -> {P2, Script};
                    {path_parts, P2, S2, _} -> {P2, S2}
                end;
            {false, _} -> {Path, Script}
        end,
    {FPath, FScript, PathInfo}.

-spec explode_path(Path :: binary()) -> {path, NewPath :: list()} | {path_parts, NewPath :: list(), Script :: list(), PathInfo :: list()}.
explode_path(P) ->
    Path = wf:to_list(P),
    case string:str(Path, ".") of
        0 -> {path, string:strip(Path, right, $/)};
        _ ->
            Tokens = string:tokens(Path, "/"),
            {P1, H, I} = parse_path(Tokens, []),
            {path_parts, P1, H, I}
    end.

-spec parse_path(Tokens :: [list()], Acc :: list()) -> {NewPath :: list(), Script :: list(), PathInfo :: list()}.
parse_path([], []) ->
    {[], [], []};
parse_path([H|T], P) ->
    case string:str(H, ".") of
        0 -> parse_path(T, P ++ "/" ++ H);
        _ -> {P, H, parse_info(T, [])}
    end;
parse_path([], P) ->
    {P, [], []}.

parse_info([H|T], I) ->
    parse_info(T, I ++ "/" ++ H);
parse_info([], I) ->
    I.

rewrite(Subject) ->
    rewrite(Subject, vhost(rewrite, [])).
rewrite(Subject, [RewRule|H]) ->
    case element(1, RewRule) of
        S when S =:= Subject orelse S =:= "*" -> {true, element(2, RewRule)};
        _ -> rewrite(Subject, H)
    end;
rewrite(Subject, []) ->
    {false, Subject}.

%% ===========================================================
%% Response
%% ===========================================================

ret() ->
    receive
        {ex_fcgi, _Ref, Messages} ->
            stdout(Messages);
        {ex_fcgi_timeout, _Ref} ->
            wf:error(?MODULE, "Connect timeout to FastCGI ~n", []),
            set_header_to_cowboy([{<<"retry-after">>, <<"3600">>}]),
            wf:state(status, 503),
            <<>>
    end.

stdout(Messages) -> stdout(Messages, <<>>).
stdout([{stderr, _Bin} | Messages], Acc) ->
    stdout(Messages, Acc);
stdout([{stdout, Bin} | Messages], Acc) ->
    {ok, H, B} = decode_result(Bin),
    case H of
        [] -> skip;
        _ ->
            RespH1 = case wf:state(n2o_fcgi_response_headers) of undefined -> []; RespH -> RespH end,
            wf:state(n2o_fcgi_response_headers, RespH1 ++ H)
    end,
    stdout(Messages, <<Acc/binary, B/binary>>);
stdout([{end_request, request_complete, 0}], Acc) ->
    Acc;
stdout([], Acc) ->
    <<Acc/binary, (ret())/binary>>.

decode_result(Data) -> decode_result(Data, []).

-spec decode_result(Data::binary(), AccH::list()) -> {ok, Headers::list(), Body::binary()} | {error, Reason::term()}.
decode_result(Data, AccH) ->
    case erlang:decode_packet(httph_bin, Data, []) of
        {ok, http_eoh, Rest} -> {ok, AccH, Rest};
        {ok, {http_header,_,<<"X-CGI-",_NameRest>>,_,_Value}, Rest} -> decode_result(Rest, AccH);
        {ok, {http_header,_Len,Field,_,Value}, Rest} -> decode_result(Rest, AccH++[{wf:to_binary(Field),Value}]);
        {ok, {http_error,_Value}, _Rest} -> {ok, [], Data};
        {more, undefined} -> {ok, [], Data}; % decode_packet cannot parsed <<"\n">>
        {more, _} -> decode_result(Data, []); % try again
        {error, Reason} -> {error, Reason}
    end.

set_header_to_cowboy(Hs, _Len) ->
    case Hs of
        undefined -> ok;
        _ ->
            %% @todo Use these default headers, if server will not to do that.
            %% Hs1 = lists:ukeymerge(1, Hs, [{<<"content-length">>, wf:to_binary(Len)}]),
            %% Hs2 = lists:ukeymerge(1, Hs1, [{<<"Content-Type">>,<<"text/html; charset=UTF-8">>}]),
            S = case lists:keyfind(<<"Status">>, 1, Hs) of
                    false -> ?DEF_RESP_STATUS;
                    {_, <<Code:3/binary, _/binary>>} -> wf:to_integer(Code)
                end,
            wf:state(status, S),
            set_header_to_cowboy(Hs)
    end.
set_header_to_cowboy([H|T]) ->
    wf:header(header_key_to_lower(element(1,H), <<>>), element(2,H)),
    set_header_to_cowboy(T);
set_header_to_cowboy([]) -> ok.


-spec binary_join([binary()], binary()) -> binary().
binary_join([], _Sep) ->
    <<>>;
binary_join([Part], _Sep) ->
    Part;
binary_join([Head|Tail], Sep) ->
    lists:foldl(fun (Value, Acc) -> <<Acc/binary, Sep/binary, Value/binary>> end, Head, Tail).

%% @todo If using lib of Cowboy, then...
%% -include_lib("cowlib/include/cow_inline.hrl").
%% header_key_to_lower(<<>>, Acc) ->
%%     Acc;
%% header_key_to_lower(<<C, Rest/bits>>, Acc) ->
%%     case C of
%%         ?INLINE_LOWERCASE(header_key_to_lower, Rest, Acc)
%% end.
header_key_to_lower(Bit, _Acc) ->
    wf:to_binary(string:to_lower(wf:to_list(Bit))).

terminate() ->
    wf:state(vhost, []),
    wf:state(n2o_fcgi_response_headers, []).
