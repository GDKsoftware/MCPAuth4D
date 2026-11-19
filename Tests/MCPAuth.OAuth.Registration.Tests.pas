unit MCPAuth.OAuth.Registration.Tests;

interface

uses
  System.JSON,
  DUnitX.TestFramework,
  MCPAuth.Clock.Interfaces,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.OAuth.RedirectPolicy,
  MCPAuth.OAuth.Registration;

type
  [TestFixture]
  TClientRegistrationTests = class
  private
    FClock: IClock;
    FClients: IClientRepository;
    FPolicy: TRedirectPolicy;
    FRegistration: TClientRegistration;

    function RegisterJson(const Json: string): TJSONObject;
    procedure AssertRejected(const Json, ExpectedCode: string);

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure RegistrationStoresClientAndReturnsId;

    [Test]
    procedure RegistrationWithoutRedirectUrisFails;

    [Test]
    procedure RegistrationWithDisallowedRedirectFails;

    [Test]
    procedure RegistrationRequestingClientSecretAuthFails;

    [Test]
    procedure ClientNameIsTruncatedTo100Chars;

    [Test]
    procedure UnsupportedGrantTypeFails;

    [Test]
    procedure UnsupportedResponseTypeFails;

    [Test]
    procedure ExplicitNoneAuthMethodIsAccepted;

    [Test]
    procedure RedirectUrisThatAreNotStringsFail;

    [Test]
    procedure TooManyRedirectUrisFail;

    [Test]
    procedure TooLongRedirectUriFails;

    [Test]
    procedure IssuedAtIsUnixSecondsFromClock;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  MCPAuth.Fakes.Clock,
  MCPAuth.Secret.Token,
  MCPAuth.Store.Memory,
  MCPAuth.OAuth.Errors,
  MCPAuth.OAuth.Types;

const
  ClaudeCallback = 'https://claude.ai/api/mcp/auth_callback';

{ TClientRegistrationTests }

procedure TClientRegistrationTests.Setup;
begin
  FClock := TFakeClock.Create(EncodeDateTime(2026, 1, 2, 3, 4, 5, 0));
  FClients := TMemoryStore.CreateSet(FClock).Clients;
  FPolicy := TRedirectPolicy.Create([]);
  FRegistration := TClientRegistration.Create(FClients, FPolicy, TTokenGenerator.Create, FClock);
end;

procedure TClientRegistrationTests.TearDown;
begin
  FRegistration.Free;
  FPolicy.Free;
end;

function TClientRegistrationTests.RegisterJson(const Json: string): TJSONObject;
begin
  const Request = TJSONObject.ParseJSONValue(Json) as TJSONObject;
  try
    Result := FRegistration.Register(Request);
  finally
    Request.Free;
  end;
end;

procedure TClientRegistrationTests.AssertRejected(const Json, ExpectedCode: string);
begin
  var Code := '';
  try
    RegisterJson(Json).Free;
  except
    on E: EOAuthError do
      Code := E.ErrorCode;
  end;

  Assert.AreEqual(ExpectedCode, Code);
end;

procedure TClientRegistrationTests.RegistrationStoresClientAndReturnsId;
begin
  const Response = RegisterJson('{"client_name":"Claude","redirect_uris":["' + ClaudeCallback + '"]}');
  try
    const ClientId = Response.GetValue<string>('client_id');
    Assert.IsNotEmpty(ClientId);
    Assert.AreEqual('none', Response.GetValue<string>('token_endpoint_auth_method'));
    Assert.IsNull(Response.GetValue('client_secret'));

    var Stored: TOAuthClient;
    Assert.IsTrue(FClients.TryGet(ClientId, Stored));
    Assert.AreEqual('Claude', Stored.ClientName);
    Assert.AreEqual(ClaudeCallback, Stored.RedirectUris[0]);
  finally
    Response.Free;
  end;
end;

procedure TClientRegistrationTests.RegistrationWithoutRedirectUrisFails;
begin
  AssertRejected('{"client_name":"x"}', TOAuthErrorCode.InvalidRedirectUri);
  AssertRejected('{"client_name":"x","redirect_uris":[]}', TOAuthErrorCode.InvalidRedirectUri);
end;

procedure TClientRegistrationTests.RegistrationWithDisallowedRedirectFails;
begin
  AssertRejected('{"redirect_uris":["https://evil.example.com/cb"]}', TOAuthErrorCode.InvalidRedirectUri);
  AssertRejected('{"redirect_uris":["' + ClaudeCallback + '","https://evil.example.com/cb"]}', TOAuthErrorCode.InvalidRedirectUri);
end;

procedure TClientRegistrationTests.RegistrationRequestingClientSecretAuthFails;
begin
  AssertRejected('{"redirect_uris":["' + ClaudeCallback + '"],"token_endpoint_auth_method":"client_secret_basic"}',
                 TOAuthErrorCode.InvalidClientMetadata);
end;

procedure TClientRegistrationTests.ClientNameIsTruncatedTo100Chars;
begin
  const LongName = StringOfChar('a', 150);
  const Response = RegisterJson('{"client_name":"' + LongName + '","redirect_uris":["' + ClaudeCallback + '"]}');
  try
    Assert.AreEqual(100, Response.GetValue<string>('client_name').Length);

    var Stored: TOAuthClient;
    Assert.IsTrue(FClients.TryGet(Response.GetValue<string>('client_id'), Stored));
    Assert.AreEqual(100, Stored.ClientName.Length);
  finally
    Response.Free;
  end;
end;

procedure TClientRegistrationTests.UnsupportedGrantTypeFails;
begin
  AssertRejected('{"redirect_uris":["' + ClaudeCallback + '"],"grant_types":["authorization_code","client_credentials"]}',
                 TOAuthErrorCode.InvalidClientMetadata);
end;

procedure TClientRegistrationTests.UnsupportedResponseTypeFails;
begin
  AssertRejected('{"redirect_uris":["' + ClaudeCallback + '"],"response_types":["token"]}',
                 TOAuthErrorCode.InvalidClientMetadata);
end;

procedure TClientRegistrationTests.ExplicitNoneAuthMethodIsAccepted;
begin
  const Response = RegisterJson('{"redirect_uris":["' + ClaudeCallback + '"],"token_endpoint_auth_method":"none",' +
                                '"grant_types":["authorization_code"],"response_types":["code"]}');
  try
    Assert.AreEqual('none', Response.GetValue<string>('token_endpoint_auth_method'));
  finally
    Response.Free;
  end;
end;

procedure TClientRegistrationTests.TooManyRedirectUrisFail;
begin
  var Uris: TArray<string> := [];
  for var Index := 1 to 10 do
  begin
    Uris := Uris + [Format('"http://localhost:%d/callback"', [7000 + Index])];
  end;
  RegisterJson(Format('{"redirect_uris":[%s]}', [string.Join(',', Uris)])).Free;

  Uris := Uris + ['"http://localhost:7011/callback"'];
  AssertRejected(Format('{"redirect_uris":[%s]}', [string.Join(',', Uris)]), TOAuthErrorCode.InvalidRedirectUri);
end;

procedure TClientRegistrationTests.TooLongRedirectUriFails;
begin
  const LongUri = 'http://localhost:7000/' + StringOfChar('a', 2048);

  AssertRejected(Format('{"redirect_uris":["%s"]}', [LongUri]), TOAuthErrorCode.InvalidRedirectUri);
end;

procedure TClientRegistrationTests.RedirectUrisThatAreNotStringsFail;
begin
  AssertRejected('{"redirect_uris":[42]}', TOAuthErrorCode.InvalidRedirectUri);
  AssertRejected('{"redirect_uris":"' + ClaudeCallback + '"}', TOAuthErrorCode.InvalidRedirectUri);
end;

procedure TClientRegistrationTests.IssuedAtIsUnixSecondsFromClock;
begin
  const Response = RegisterJson('{"redirect_uris":["' + ClaudeCallback + '"]}');
  try
    // The fake clock's 2026-01-02 03:04:05 UTC; a conversion from local time shifts it outside UTC.
    Assert.AreEqual<Int64>(1767323045, Response.GetValue<Int64>('client_id_issued_at'));
  finally
    Response.Free;
  end;
end;

end.
