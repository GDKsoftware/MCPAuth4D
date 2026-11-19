unit MCPAuth.Web.Server.Indy;

interface

uses
  IdContext,
  IdCustomHTTPServer,
  IdHeaderList,
  IdHTTPServer,
  MCPAuth.Web.Types,
  MCPAuth.Web.Router;

type
  // Serves one router over HTTP. The same class runs twice: once for the public router and once, on its own
  // listener, for the internal router. It binds only to the given address (loopback unless told otherwise).
  TMCPAuthWebServer = class
  private
    FRouter: TWebRouter;
    FServer: TIdHTTPServer;
    FPort: Word;
    FBindAddress: string;
    FReadTimeoutMs: Integer;

    class function IsBodyTooLarge(const Headers: TIdHeaderList): Boolean; static;
    class function IsChunked(const Headers: TIdHeaderList): Boolean; static;
    class function Utf8FromEightBit(const Text: string): string; static;
    class function HeaderSafe(const Value: string): string; static;
    class procedure DiscardBody(const Context: TIdContext; const Headers: TIdHeaderList); static;

    procedure HandleConnect(AContext: TIdContext);
    procedure HandleCommand(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    procedure HandleHeadersAvailable(AContext: TIdContext; const AUri: string; AHeaders: TIdHeaderList; var VContinueProcessing: Boolean);
    procedure HandleHeadersBlocked(AContext: TIdContext; AHeaders: TIdHeaderList; var VResponseNo: Integer; var VResponseText, VContentText: string);

    function ToWebRequest(const Context: TIdContext; const RequestInfo: TIdHTTPRequestInfo): TWebRequest;
    function ReadBody(const RequestInfo: TIdHTTPRequestInfo): string;
    function RouteRequest(const Request: TWebRequest): TWebResponse;
    procedure WriteResponse(const Response: TWebResponse; const ResponseInfo: TIdHTTPResponseInfo);

    function GetMaxConnections: Integer;
    procedure SetMaxConnections(const Value: Integer);

  public
    const DEFAULT_MAX_CONNECTIONS = 256;
    const DEFAULT_READ_TIMEOUT_MS = 30000;

    constructor Create(const Router: TWebRouter; const Port: Word; const BindAddress: string = '127.0.0.1');
    destructor Destroy; override;

    procedure Start;
    procedure Stop;

    // The port the listener actually uses; differs from the requested port when that was 0.
    function BoundPort: Word;

    // Connections above this limit are closed at once; 0 means no limit. Set before Start.
    property MaxConnections: Integer read GetMaxConnections write SetMaxConnections;

    // A client that sends nothing for this long while a request is read gets its connection closed,
    // so slow clients cannot hold threads. Set before Start.
    property ReadTimeoutMs: Integer read FReadTimeoutMs write FReadTimeoutMs;
  end;

implementation

uses
  System.SysUtils,
  System.Classes,
  Spring.Collections,
  IdGlobal,
  IdSocketHandle,
  MCPAuth.Web.ErrorLog;

const
  MaxBodyBytes = 1024 * 1024;
  StatusPayloadTooLarge = 413;
  StatusLengthRequired = 411;
  StatusServerError = 500;
  ServerErrorBody = '{"error":"server_error"}';
  TooLargeBody = '{"error":"request_too_large"}';
  LengthRequiredBody = '{"error":"length_required"}';
  ContentLengthHeader = 'Content-Length';
  TransferEncodingHeader = 'Transfer-Encoding';
  ChunkedEncoding = 'chunked';
  SetCookieHeader = 'Set-Cookie';
  CharsetUtf8 = 'utf-8';
  EightBitMask = $FF;
  MaxDiscardBytes = 8 * 1024 * 1024;

{ TMCPAuthWebServer }

class function TMCPAuthWebServer.IsBodyTooLarge(const Headers: TIdHeaderList): Boolean;
begin
  const DeclaredLength = StrToInt64Def(Headers.Values[ContentLengthHeader], 0);
  Result := (DeclaredLength > MaxBodyBytes);
end;

class function TMCPAuthWebServer.IsChunked(const Headers: TIdHeaderList): Boolean;
begin
  Result := Headers.Values[TransferEncodingHeader].ToLower.Contains(ChunkedEncoding);
end;

class function TMCPAuthWebServer.Utf8FromEightBit(const Text: string): string;
begin
  // Indy reads a form body as 8-bit text, so every character is one byte of the original UTF-8 body.
  var Bytes: TBytes;
  SetLength(Bytes, Text.Length);
  for var Index := 0 to Text.Length - 1 do
  begin
    Bytes[Index] := Byte(Ord(Text.Chars[Index]) and EightBitMask);
  end;

  Result := TEncoding.UTF8.GetString(Bytes);
end;

class function TMCPAuthWebServer.HeaderSafe(const Value: string): string;
begin
  // A line break in a header value would let a value split the response.
  Result := Value.Replace(#13, '').Replace(#10, '');
end;

class procedure TMCPAuthWebServer.DiscardBody(const Context: TIdContext; const Headers: TIdHeaderList);
begin
  // A client that is still sending when the answer arrives sees a reset instead of the 413. Reading a body of
  // moderate size without keeping it lets the answer arrive; a larger one just gets the connection closed.
  const DeclaredLength = StrToInt64Def(Headers.Values[ContentLengthHeader], 0);
  const IsDiscardable = ((DeclaredLength > 0) and (DeclaredLength <= MaxDiscardBytes));
  if not IsDiscardable then
    Exit;

  try
    Context.Connection.IOHandler.Discard(DeclaredLength);
  except
    on Exception do
      Context.Connection.Disconnect;
  end;
end;

constructor TMCPAuthWebServer.Create(const Router: TWebRouter; const Port: Word; const BindAddress: string);
begin
  inherited Create;

  FRouter := Router;
  FPort := Port;
  FBindAddress := BindAddress;

  FServer := TIdHTTPServer.Create(nil);
  FServer.ParseParams := False;
  FServer.OnCommandGet := HandleCommand;
  FServer.OnCommandOther := HandleCommand;
  FServer.OnHeadersAvailable := HandleHeadersAvailable;
  FServer.OnHeadersBlocked := HandleHeadersBlocked;
  FServer.OnConnect := HandleConnect;
  FServer.MaxConnections := DEFAULT_MAX_CONNECTIONS;
  FReadTimeoutMs := DEFAULT_READ_TIMEOUT_MS;
end;

destructor TMCPAuthWebServer.Destroy;
begin
  Stop;
  FServer.Free;
  inherited Destroy;
end;

procedure TMCPAuthWebServer.Start;
begin
  if FServer.Active then
    Exit;

  FServer.Bindings.Clear;
  const Binding = FServer.Bindings.Add;
  Binding.IP := FBindAddress;
  Binding.Port := FPort;

  FServer.Active := True;
end;

procedure TMCPAuthWebServer.Stop;
begin
  FServer.Active := False;
end;

function TMCPAuthWebServer.BoundPort: Word;
begin
  const IsListening = (FServer.Active and (FServer.Bindings.Count > 0));
  if IsListening then
    Result := FServer.Bindings[0].Port
  else
    Result := FPort;
end;

function TMCPAuthWebServer.GetMaxConnections: Integer;
begin
  Result := FServer.MaxConnections;
end;

procedure TMCPAuthWebServer.SetMaxConnections(const Value: Integer);
begin
  FServer.MaxConnections := Value;
end;

procedure TMCPAuthWebServer.HandleConnect(AContext: TIdContext);
begin
  AContext.Connection.IOHandler.ReadTimeout := FReadTimeoutMs;
end;

procedure TMCPAuthWebServer.HandleHeadersAvailable(AContext: TIdContext; const AUri: string; AHeaders: TIdHeaderList; var VContinueProcessing: Boolean);
begin
  // The size is checked on the declared length, before any of the body is read.
  VContinueProcessing := not (IsBodyTooLarge(AHeaders) or IsChunked(AHeaders));
end;

procedure TMCPAuthWebServer.HandleHeadersBlocked(AContext: TIdContext; AHeaders: TIdHeaderList; var VResponseNo: Integer; var VResponseText, VContentText: string);
begin
  if IsChunked(AHeaders) then
  begin
    VResponseNo := StatusLengthRequired;
    VContentText := LengthRequiredBody;
  end
  else
  begin
    DiscardBody(AContext, AHeaders);
    VResponseNo := StatusPayloadTooLarge;
    VContentText := TooLargeBody;
  end;
end;

procedure TMCPAuthWebServer.HandleCommand(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
begin
  const Request = ToWebRequest(AContext, ARequestInfo);
  const Response = RouteRequest(Request);

  WriteResponse(Response, AResponseInfo);
end;

function TMCPAuthWebServer.ToWebRequest(const Context: TIdContext; const RequestInfo: TIdHTTPRequestInfo): TWebRequest;
begin
  Result := Default(TWebRequest);
  Result.Method        := RequestInfo.Command;
  Result.Path          := RequestInfo.Document;
  Result.Query         := RequestInfo.QueryParams;
  Result.Body          := ReadBody(RequestInfo);
  Result.ContentType   := RequestInfo.ContentType;
  Result.RemoteAddress := Context.Binding.PeerIP;
  Result.Headers       := TCollections.CreateDictionary<string, string>;
  Result.Cookies       := TCollections.CreateDictionary<string, string>;

  for var Index := 0 to RequestInfo.RawHeaders.Count - 1 do
  begin
    Result.Headers[RequestInfo.RawHeaders.Names[Index]] := RequestInfo.RawHeaders.Values[RequestInfo.RawHeaders.Names[Index]];
  end;

  for var Index := 0 to RequestInfo.Cookies.Count - 1 do
  begin
    Result.Cookies[RequestInfo.Cookies[Index].CookieName] := RequestInfo.Cookies[Index].Value;
  end;
end;

function TMCPAuthWebServer.ReadBody(const RequestInfo: TIdHTTPRequestInfo): string;
begin
  // Indy keeps a form body in FormParams and frees the stream; every other body stays in the stream.
  const HasStream = Assigned(RequestInfo.PostStream);
  if not HasStream then
    Exit(Utf8FromEightBit(RequestInfo.FormParams));

  const Stream = TBytesStream.Create;
  try
    RequestInfo.PostStream.Position := 0;
    Stream.CopyFrom(RequestInfo.PostStream, 0);
    Result := TEncoding.UTF8.GetString(Stream.Bytes, 0, Stream.Size);
  finally
    Stream.Free;
  end;
end;

function TMCPAuthWebServer.RouteRequest(const Request: TWebRequest): TWebResponse;
begin
  try
    Result := FRouter.Dispatch(Request);
  except
    on E: Exception do
    begin
      // Only the class name and the path are logged: the request itself may hold tokens, codes or addresses.
      TWebErrorLog.Unexpected(E, Request.Path);
      Result := TWebResponse.Json(StatusServerError, ServerErrorBody);
      Result.AddHeader('Cache-Control', 'no-store');
    end;
  end;
end;

procedure TMCPAuthWebServer.WriteResponse(const Response: TWebResponse; const ResponseInfo: TIdHTTPResponseInfo);
begin
  ResponseInfo.ResponseNo := Response.StatusCode;

  const HasBody = not Response.ContentType.IsEmpty;
  if HasBody then
  begin
    ResponseInfo.ContentType := Response.ContentType.Split([';'])[0].Trim;
    ResponseInfo.CharSet := CharsetUtf8;
    ResponseInfo.ContentText := Response.Body;
  end;

  const HasLocation = not Response.Location.IsEmpty;
  if HasLocation then
    ResponseInfo.Location := HeaderSafe(Response.Location);

  for var Cookie in Response.SetCookies do
  begin
    ResponseInfo.CustomHeaders.AddValue(SetCookieHeader, HeaderSafe(Cookie));
  end;

  for var Header in Response.ExtraHeaders do
  begin
    ResponseInfo.CustomHeaders.AddValue(HeaderSafe(Header.Key), HeaderSafe(Header.Value));
  end;
end;

end.
