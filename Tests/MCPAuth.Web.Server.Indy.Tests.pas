unit MCPAuth.Web.Server.Indy.Tests;

interface

uses
  System.SysUtils,
  System.Net.HttpClient,
  DUnitX.TestFramework,
  MCPAuth.Web.Types,
  MCPAuth.Web.Router,
  MCPAuth.Web.Server.Indy;

type
  EDeliberateFailure = class(Exception);

  [TestFixture]
  TMCPAuthWebServerTests = class
  private
    FRouter: TWebRouter;
    FServer: TMCPAuthWebServer;
    FClient: THTTPClient;
    FLogLines: string;

    function Url(const PathAndQuery: string): string;
    function PostText(const PathAndQuery, ContentType, Body: string): IHTTPResponse;
    function EchoOf(const Request: TWebRequest): TWebResponse;
    procedure RegisterRoutes;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure IndyServerServesMetadataOnLoopback;

    [Test]
    procedure RequestPartsReachTheRouterRaw;

    [Test]
    procedure JsonBodyReachesTheRouterAsUtf8;

    [Test]
    procedure RedirectHeadersAndMultipleCookiesAreSent;

    [Test]
    procedure BodyOverOneMegabyteGets413;

    [Test]
    procedure UnexpectedExceptionBecomes500AndIsLoggedWithoutDetails;

    [Test]
    procedure ServerListensOnlyOnTheGivenAddress;

    [Test]
    procedure SilentClientIsDisconnectedAfterReadTimeout;
  end;

implementation

uses
  System.Classes,
  System.JSON,
  System.Net.URLClient,
  System.Diagnostics,
  IdTCPClient,
  IdExceptionCore,
  IdStack,
  IdException,
  MCPServer.Logger,
  MCPAuth.OAuth.Settings,
  MCPAuth.OAuth.Metadata;

const
  Loopback = '127.0.0.1';
  OtherLoopback = '127.0.0.2';
  FormContentType = 'application/x-www-form-urlencoded';
  JsonContentType = 'application/json; charset=utf-8';
  MaxBodyBytes = 1024 * 1024;
  StatusOk = 200;
  StatusFound = 302;
  StatusPayloadTooLarge = 413;
  StatusServerError = 500;
  SecretValue = 'secret-token-123';
  ShortReadTimeoutMs = 200;
  ClientReadTimeoutMs = 5000;
  PromptDisconnectMs = 3000;

{ TMCPAuthWebServerTests }

procedure TMCPAuthWebServerTests.Setup;
begin
  FLogLines := '';
  FRouter := TWebRouter.Create;
  RegisterRoutes;

  FServer := TMCPAuthWebServer.Create(FRouter, 0, Loopback);
  FServer.Start;

  FClient := THTTPClient.Create;
  FClient.HandleRedirects := False;
end;

procedure TMCPAuthWebServerTests.TearDown;
begin
  TLogger.OnLogMessage := nil;
  FClient.Free;
  FServer.Free;
  FRouter.Free;
end;

procedure TMCPAuthWebServerTests.RegisterRoutes;
begin
  FRouter.Add('GET', '/.well-known/oauth-authorization-server',
    function(const Request: TWebRequest): TWebResponse
    begin
      const Metadata = TAuthorizationServerMetadata.Build(TMCPAuthSettings.Defaults('https://auth.example.test'));
      try
        Result := TWebResponse.Json(StatusOk, Metadata.ToJSON);
      finally
        Metadata.Free;
      end;
    end);

  FRouter.Add('POST', '/echo', EchoOf);

  FRouter.Add('GET', '/multi',
    function(const Request: TWebRequest): TWebResponse
    begin
      Result := TWebResponse.Redirect('/account');
      Result.AddCookie('first=1; Path=/; HttpOnly');
      Result.AddCookie('second=2; Path=/; Max-Age=0');
      Result.AddHeader('Cache-Control', 'no-store');
    end);

  FRouter.Add('POST', '/boom',
    function(const Request: TWebRequest): TWebResponse
    begin
      raise EDeliberateFailure.Create(SecretValue);
    end);
end;

function TMCPAuthWebServerTests.EchoOf(const Request: TWebRequest): TWebResponse;
begin
  var Cookie := '';
  Request.TryGetCookie('mcpauth_session', Cookie);

  const Echo = TJSONObject.Create;
  try
    Echo.AddPair('method', Request.Method);
    Echo.AddPair('path', Request.Path);
    Echo.AddPair('query', Request.Query);
    Echo.AddPair('body', Request.Body);
    Echo.AddPair('content_type', Request.ContentType);
    Echo.AddPair('remote', Request.RemoteAddress);
    Echo.AddPair('session', Cookie);

    Result := TWebResponse.Json(StatusOk, Echo.ToJSON);
  finally
    Echo.Free;
  end;
end;

function TMCPAuthWebServerTests.Url(const PathAndQuery: string): string;
begin
  Result := Format('http://%s:%d%s', [Loopback, FServer.BoundPort, PathAndQuery]);
end;

function TMCPAuthWebServerTests.PostText(const PathAndQuery, ContentType, Body: string): IHTTPResponse;
begin
  const Content = TStringStream.Create(Body, TEncoding.UTF8);
  try
    const Headers: TNetHeaders = [TNetHeader.Create('Content-Type', ContentType)];
    Result := FClient.Post(Url(PathAndQuery), Content, nil, Headers);
  finally
    Content.Free;
  end;
end;

procedure TMCPAuthWebServerTests.IndyServerServesMetadataOnLoopback;
begin
  const Response = FClient.Get(Url('/.well-known/oauth-authorization-server'));

  Assert.AreEqual(StatusOk, Response.StatusCode);
  Assert.AreNotEqual<Integer>(0, FServer.BoundPort, 'port 0 resolves to a real port');
  Assert.StartsWith('application/json', Response.MimeType);
  Assert.Contains(Response.ContentAsString, 'https://auth.example.test');
end;

procedure TMCPAuthWebServerTests.RequestPartsReachTheRouterRaw;
begin
  FClient.CustomHeaders['Cookie'] := 'other=1; mcpauth_session=abc123';

  const Response = PostText('/echo?a=%C3%A9&b=1', FormContentType, 'x=%C3%A9&y=1+2');

  Assert.AreEqual(StatusOk, Response.StatusCode, Response.ContentAsString);
  const Echo = TJSONObject.ParseJSONValue(Response.ContentAsString) as TJSONObject;
  try
    Assert.AreEqual('POST', Echo.GetValue<string>('method'));
    Assert.AreEqual('/echo', Echo.GetValue<string>('path'));
    Assert.AreEqual('a=%C3%A9&b=1', Echo.GetValue<string>('query'), 'query stays encoded and apart from the body');
    Assert.AreEqual('x=%C3%A9&y=1+2', Echo.GetValue<string>('body'), 'body stays encoded and apart from the query');
    Assert.StartsWith(FormContentType, Echo.GetValue<string>('content_type'));
    Assert.AreEqual(Loopback, Echo.GetValue<string>('remote'));
    Assert.AreEqual('abc123', Echo.GetValue<string>('session'));
  finally
    Echo.Free;
  end;
end;

procedure TMCPAuthWebServerTests.JsonBodyReachesTheRouterAsUtf8;
begin
  const Text = '{"name":"caf' + Char($E9) + '"}';

  const Response = PostText('/echo', JsonContentType, Text);

  Assert.AreEqual(StatusOk, Response.StatusCode, Response.ContentAsString);
  const Echo = TJSONObject.ParseJSONValue(Response.ContentAsString) as TJSONObject;
  try
    Assert.AreEqual(Text, Echo.GetValue<string>('body'));
  finally
    Echo.Free;
  end;
end;

procedure TMCPAuthWebServerTests.RedirectHeadersAndMultipleCookiesAreSent;
begin
  const Response = FClient.Get(Url('/multi'));

  Assert.AreEqual(StatusFound, Response.StatusCode);
  Assert.AreEqual('/account', Response.HeaderValue['Location']);
  Assert.AreEqual('no-store', Response.HeaderValue['Cache-Control']);
  Assert.AreEqual<Integer>(2, Response.Cookies.Count, 'every cookie gets its own header');
  Assert.AreEqual('first', Response.Cookies[0].Name);
  Assert.AreEqual('second', Response.Cookies[1].Name);
end;

procedure TMCPAuthWebServerTests.BodyOverOneMegabyteGets413;
begin
  const Body = StringOfChar('a', MaxBodyBytes + 1);

  const Response = PostText('/echo', FormContentType, Body);

  Assert.AreEqual(StatusPayloadTooLarge, Response.StatusCode);
end;

procedure TMCPAuthWebServerTests.UnexpectedExceptionBecomes500AndIsLoggedWithoutDetails;
begin
  TLogger.OnLogMessage :=
    procedure(const Message: string)
    begin
      FLogLines := FLogLines + Message + sLineBreak;
    end;

  const Response = PostText('/boom?token=query-secret', FormContentType, 'password=body-secret');
  TLogger.OnLogMessage := nil;

  Assert.AreEqual(StatusServerError, Response.StatusCode);
  Assert.Contains(Response.ContentAsString, 'server_error');
  Assert.IsFalse(Response.ContentAsString.Contains(SecretValue), 'no exception message in the response');

  Assert.Contains(FLogLines, 'EDeliberateFailure');
  Assert.Contains(FLogLines, '/boom');
  Assert.IsFalse(FLogLines.Contains(SecretValue), 'no exception message in the log');
  Assert.IsFalse(FLogLines.Contains('query-secret'), 'no query string in the log');
  Assert.IsFalse(FLogLines.Contains('body-secret'), 'no body in the log');
end;

procedure TMCPAuthWebServerTests.ServerListensOnlyOnTheGivenAddress;
begin
  const OtherAddressUrl = Format('http://%s:%d/echo', [OtherLoopback, FServer.BoundPort]);

  Assert.WillRaise(
    procedure
    begin
      FClient.Get(OtherAddressUrl);
    end,
    ENetHTTPClientException);
end;

procedure TMCPAuthWebServerTests.SilentClientIsDisconnectedAfterReadTimeout;
begin
  const Server = TMCPAuthWebServer.Create(FRouter, 0, Loopback);
  try
    Server.ReadTimeoutMs := ShortReadTimeoutMs;
    Server.Start;

    const Client = TIdTCPClient.Create(nil);
    try
      Client.Host := Loopback;
      Client.Port := Server.BoundPort;
      Client.ReadTimeout := ClientReadTimeoutMs;
      Client.Connect;

      const Watch = TStopwatch.StartNew;
      var IsClosedByServer := False;
      while not IsClosedByServer and (Watch.ElapsedMilliseconds < ClientReadTimeoutMs) do
      begin
        try
          Client.IOHandler.ReadLn;
        except
          on EIdConnClosedGracefully do
            IsClosedByServer := True;
          on EIdSocketError do
            IsClosedByServer := True;
        end;
      end;

      Assert.IsTrue(IsClosedByServer, 'the server closes a connection that sends nothing');
      Assert.IsTrue(Watch.ElapsedMilliseconds < PromptDisconnectMs, 'the connection is closed after the read timeout');
    finally
      Client.Free;
    end;
  finally
    Server.Free;
  end;
end;

end.
