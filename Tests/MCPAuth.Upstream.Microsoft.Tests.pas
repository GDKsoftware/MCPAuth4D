unit MCPAuth.Upstream.Microsoft.Tests;

interface

uses
  DUnitX.TestFramework,
  MCPAuth.Fakes.Clock,
  MCPAuth.Fakes.UpstreamHttp,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Upstream.Http.Interfaces,
  MCPAuth.Upstream.Interfaces;

type
  [TestFixture]
  TMicrosoftUpstreamProviderTests = class
  private
    FClock: TFakeClock;
    FClockReference: IClock;
    FHttp: TFakeUpstreamHttp;
    FHttpReference: IUpstreamHttp;
    FProvider: IUpstreamProvider;

    function TokenResponseJson(const IdToken: string): string;
    function RaisedMessageOfRefresh(const RefreshToken: string; out RaisedClass: TClass): string;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure NameIsMicrosoft;

    [Test]
    procedure AuthorizationUrlContainsPkceStateAndScopes;

    [Test]
    procedure ExchangeCodeMapsIdentityFromIdToken;

    [Test]
    procedure ExchangeCodeWithoutTenantRaises;

    [Test]
    procedure RefreshSendsRefreshGrantWithoutIdentity;

    [Test]
    procedure RefreshInvalidGrantRaisesGrantRevoked;

    [Test]
    procedure ServerErrorRaisesUpstreamErrorWithoutTokens;

    [Test]
    procedure ErrorCodeWithUnexpectedCharactersIsNotEchoed;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  MCPAuth.Fakes.Jwt,
  MCPAuth.Upstream.Exceptions,
  MCPAuth.Upstream.Types,
  MCPAuth.Upstream.Credential.Secret,
  MCPAuth.Upstream.Microsoft;

const
  ClientId = 'client-1';
  ClientSecret = 'secret-value-1';
  RedirectUri = 'https://auth.example.com/callback/microsoft';
  AuthorizeEndpoint = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize';
  TokenEndpoint = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token';
  AccessTokenValue = 'access-token-value-1';
  RefreshTokenValue = 'refresh-token-value-1';
  NewRefreshTokenValue = 'refresh-token-value-2';
  GrantedScope = 'openid profile offline_access Mail.Read';
  IdentityClaims = '{"tid":"Tenant-1","oid":"Object-1","name":"Ada Lovelace","preferred_username":"ada@example.com"}';

{ TMicrosoftUpstreamProviderTests }

procedure TMicrosoftUpstreamProviderTests.Setup;
begin
  FClock          := TFakeClock.Create(EncodeDateTime(2026, 11, 19, 10, 0, 0, 0));
  FClockReference := FClock;
  FHttp           := TFakeUpstreamHttp.Create;
  FHttpReference  := FHttp;

  const Credential: IClientCredential = TClientSecretCredential.Create(ClientId, ClientSecret);
  FProvider := TMicrosoftUpstreamProvider.Create(ClientId, Credential, ['Mail.Read', 'offline_access'], FHttpReference, FClockReference);
end;

procedure TMicrosoftUpstreamProviderTests.TearDown;
begin
  FProvider       := nil;
  FHttp           := nil;
  FHttpReference  := nil;
  FClock          := nil;
  FClockReference := nil;
end;

function TMicrosoftUpstreamProviderTests.TokenResponseJson(const IdToken: string): string;
begin
  const Template = '{"token_type":"Bearer","access_token":"%s","refresh_token":"%s","expires_in":3600,"scope":"%s","id_token":"%s"}';

  Result := Format(Template, [AccessTokenValue, NewRefreshTokenValue, GrantedScope, IdToken]);
end;

function TMicrosoftUpstreamProviderTests.RaisedMessageOfRefresh(const RefreshToken: string; out RaisedClass: TClass): string;
begin
  RaisedClass := nil;
  Result      := '';
  try
    FProvider.Refresh(RefreshToken);
  except
    on E: EUpstreamError do
    begin
      RaisedClass := E.ClassType;
      Result      := E.Message;
    end;
  end;
end;

procedure TMicrosoftUpstreamProviderTests.NameIsMicrosoft;
begin
  Assert.AreEqual('microsoft', FProvider.Name);
end;

procedure TMicrosoftUpstreamProviderTests.AuthorizationUrlContainsPkceStateAndScopes;
begin
  const Url = FProvider.AuthorizationUrl('state-1', 'challenge-1', RedirectUri);

  Assert.StartsWith(AuthorizeEndpoint + '?', Url);
  Assert.Contains(Url, 'client_id=client-1');
  Assert.Contains(Url, 'response_type=code');
  Assert.Contains(Url, 'redirect_uri=https%3A%2F%2Fauth.example.com%2Fcallback%2Fmicrosoft');
  Assert.Contains(Url, 'state=state-1');
  Assert.Contains(Url, 'code_challenge=challenge-1');
  Assert.Contains(Url, 'code_challenge_method=S256');
  Assert.Contains(Url, 'prompt=select_account');
  Assert.Contains(Url, 'scope=openid+profile+offline_access+Mail.Read&');
end;

procedure TMicrosoftUpstreamProviderTests.ExchangeCodeMapsIdentityFromIdToken;
begin
  const IdToken = TFakeJwt.Unsigned(IdentityClaims);
  FHttp.EnqueueResponse(200, TokenResponseJson(IdToken));

  const Tokens = FProvider.ExchangeCode('code-1', 'verifier-1', RedirectUri);

  const ExpectedExpiry = IncSecond(FClock.NowUtc, 3600);
  Assert.AreEqual(AccessTokenValue, Tokens.AccessToken);
  Assert.AreEqual(NewRefreshTokenValue, Tokens.RefreshToken);
  Assert.AreEqual(GrantedScope, Tokens.Scope);
  Assert.AreEqual(ExpectedExpiry, Tokens.ExpiresAtUtc, OneSecond / 10);
  Assert.AreEqual('microsoft', Tokens.Identity.Key.Provider);
  Assert.AreEqual('Tenant-1', Tokens.Identity.Key.TenantId);
  Assert.AreEqual('Object-1', Tokens.Identity.Key.ObjectId);
  Assert.AreEqual('Ada Lovelace', Tokens.Identity.DisplayName);
  Assert.AreEqual('ada@example.com', Tokens.Identity.UserName);

  const Request = FHttp.LastRequest;
  Assert.AreEqual(TokenEndpoint, Request.Url);
  Assert.AreEqual('authorization_code', Request.GetField('grant_type'));
  Assert.AreEqual('code-1', Request.GetField('code'));
  Assert.AreEqual('verifier-1', Request.GetField('code_verifier'));
  Assert.AreEqual(RedirectUri, Request.GetField('redirect_uri'));
  Assert.AreEqual(ClientId, Request.GetField('client_id'));
  Assert.AreEqual(ClientSecret, Request.GetField('client_secret'));
end;

procedure TMicrosoftUpstreamProviderTests.ExchangeCodeWithoutTenantRaises;
begin
  const IdToken = TFakeJwt.Unsigned('{"oid":"Object-1","name":"Ada Lovelace"}');
  FHttp.EnqueueResponse(200, TokenResponseJson(IdToken));

  Assert.WillRaise(
    procedure
    begin
      FProvider.ExchangeCode('code-1', 'verifier-1', RedirectUri);
    end,
    EUpstreamError);
end;

procedure TMicrosoftUpstreamProviderTests.RefreshSendsRefreshGrantWithoutIdentity;
begin
  const IdToken = TFakeJwt.Unsigned(IdentityClaims);
  FHttp.EnqueueResponse(200, TokenResponseJson(IdToken));

  const Tokens = FProvider.Refresh(RefreshTokenValue);

  Assert.AreEqual(AccessTokenValue, Tokens.AccessToken);
  Assert.AreEqual(NewRefreshTokenValue, Tokens.RefreshToken);
  Assert.IsEmpty(Tokens.Identity.Key.ObjectId);

  const Request = FHttp.LastRequest;
  Assert.AreEqual('refresh_token', Request.GetField('grant_type'));
  Assert.AreEqual(RefreshTokenValue, Request.GetField('refresh_token'));
  Assert.AreEqual(GrantedScope, Request.GetField('scope'));
  Assert.AreEqual(ClientSecret, Request.GetField('client_secret'));
end;

procedure TMicrosoftUpstreamProviderTests.RefreshInvalidGrantRaisesGrantRevoked;
begin
  FHttp.EnqueueResponse(400, '{"error":"invalid_grant","error_description":"AADSTS70000: The grant was revoked."}');

  Assert.WillRaise(
    procedure
    begin
      FProvider.Refresh(RefreshTokenValue);
    end,
    EUpstreamGrantRevoked);
end;

procedure TMicrosoftUpstreamProviderTests.ServerErrorRaisesUpstreamErrorWithoutTokens;
begin
  const Template = '{"error":"server_error","error_description":"failed for %s","access_token":"%s"}';
  const Body = Format(Template, [RefreshTokenValue, AccessTokenValue]);
  FHttp.EnqueueResponse(500, Body);

  var RaisedClass: TClass;
  const RaisedMessage = RaisedMessageOfRefresh(RefreshTokenValue, RaisedClass);

  Assert.AreEqual(EUpstreamError, RaisedClass);
  Assert.DoesNotContain(RaisedMessage, RefreshTokenValue);
  Assert.DoesNotContain(RaisedMessage, AccessTokenValue);
  Assert.DoesNotContain(RaisedMessage, 'failed for');
  Assert.Contains(RaisedMessage, '500');
end;

procedure TMicrosoftUpstreamProviderTests.ErrorCodeWithUnexpectedCharactersIsNotEchoed;
begin
  const Body = Format('{"error":"%s"}', [AccessTokenValue]);
  FHttp.EnqueueResponse(400, Body);

  var RaisedClass: TClass;
  const RaisedMessage = RaisedMessageOfRefresh(RefreshTokenValue, RaisedClass);

  Assert.AreEqual(EUpstreamError, RaisedClass);
  Assert.DoesNotContain(RaisedMessage, AccessTokenValue);
end;

end.
