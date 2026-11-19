unit MCPAuth.OAuth.Server.Tests;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MCPAuth.Fakes.Clock,
  MCPAuth.Fakes.UpstreamProvider,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.OAuth.Settings;

type
  [TestFixture]
  TAuthorizationServerTests = class
  private
    FClock: TFakeClock;
    FClockReference: IClock;
    FStores: TStoreSet;
    FProvider: TFakeUpstreamProvider;
    FProviderReference: IUpstreamProvider;
    FSettings: TMCPAuthSettings;
    FServer: IAuthorizationServer;
    FVerifier: string;

    class function QueryParam(const Url, Name: string): string; static;

    function BuildResourceRegistryJson: string;
    procedure RegisterClient;
    function AuthorizeRequest(const Resource: string): TAuthorizeRequest;
    function ObtainCode(const Resource: string): string;
    function ObtainCodeWithSession(const Resource, UserId: string): string;
    function CodeRequest(const Code: string): TTokenRequest;
    function RefreshRequest(const RefreshToken: string): TTokenRequest;
    function ObtainTokens(const Resource: string): TTokenResponse;
    function ErrorCodeOf(const Action: TProc): string;
    function IsTokenKnown(const Token: string): Boolean;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure FullCodeFlowIssuesTokensBoundToResource;

    [Test]
    procedure MissingResourceIsInvalidTarget;

    [Test]
    procedure UnknownResourceIsInvalidTarget;

    [Test]
    procedure WrongVerifierIsInvalidGrant;

    [Test]
    procedure CodeIsSingleUse;

    [Test]
    procedure ExpiredCodeIsInvalidGrant;

    [Test]
    procedure RedirectMismatchAtTokenIsInvalidGrant;

    [Test]
    procedure ResourceMismatchAtTokenIsInvalidTarget;

    [Test]
    procedure UnregisteredRedirectRaisesInvalidRedirectUri;

    [Test]
    procedure UnknownClientRaisesInvalidClient;

    [Test]
    procedure PlainChallengeMethodIsRejected;

    [Test]
    procedure OtherScopeIsInvalidScope;

    [Test]
    procedure RefreshRotatesAndOldTokenStopsWorking;

    [Test]
    procedure RefreshReuseRevokesFamily;

    [Test]
    procedure AccessTokenIsNotAcceptedAsRefreshToken;

    [Test]
    procedure DenyRedirectsWithAccessDeniedAndState;

    [Test]
    procedure ExistingSessionSkipsUpstreamLogin;

    [Test]
    procedure ApproveByOtherUserIsRejected;

    [Test]
    procedure DenyByOtherUserIsRejected;

    [Test]
    procedure UpstreamCallbackIsSingleUse;

    [Test]
    procedure ConsentInfoNamesResource;

    [Test]
    procedure LinkAccountLoginLinksToGivenUser;

    [Test]
    procedure RevokeRemovesFamily;

    [Test]
    procedure RevokeFamilyOfOtherUserIsIgnored;
  end;

implementation

uses
  System.DateUtils,
  System.NetEncoding,
  Spring.Collections,
  MCPAuth.Secret.Hash,
  MCPAuth.Secret.Token,
  MCPAuth.Secret.KeyRing,
  MCPAuth.Secret.AesGcm,
  MCPAuth.Store.Memory,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Identity.Accounts,
  MCPAuth.Identity.Access.AllowAll,
  MCPAuth.Resource.Registry.Json,
  MCPAuth.Upstream.Providers,
  MCPAuth.OAuth.Pkce,
  MCPAuth.OAuth.Errors,
  MCPAuth.OAuth.Server;

const
  Issuer = 'https://auth.example.test';
  ProviderName = 'fake';
  ClientId = 'client-1';
  ClientName = 'Test Client';
  RedirectUri = 'http://localhost:9000/callback';
  OtherRedirectUri = 'http://localhost:9000/other';
  ClientState = 'client state/1';
  ResourceA = 'https://a.example.test/mcp';
  ResourceB = 'https://b.example.test/mcp';
  UpstreamCode = 'upstream-code';
  SessionUser = 'user-1';
  OtherUser = 'user-2';
  KeyId = 'k1';
  KeyLength = 32;

{ TAuthorizationServerTests }

class function TAuthorizationServerTests.QueryParam(const Url, Name: string): string;
begin
  const QueryStart = Url.IndexOf('?');
  const Query = Url.Substring(QueryStart + 1);
  const Prefix = Format('%s=', [Name]);
  for var Field in Query.Split(['&']) do
  begin
    if Field.StartsWith(Prefix) then
    begin
      // Form encoding writes a space as '+'; a literal '+' arrives as %2B.
      const EncodedValue = Field.Substring(Prefix.Length).Replace('+', ' ');
      Exit(TNetEncoding.URL.Decode(EncodedValue));
    end;
  end;

  Result := '';
end;

procedure TAuthorizationServerTests.Setup;
begin
  FClock := TFakeClock.Create(EncodeDateTime(2026, 1, 2, 3, 4, 5, 0));
  FClockReference := FClock;
  FStores := TMemoryStore.CreateSet(FClockReference);
  FProvider := TFakeUpstreamProvider.Create(ProviderName);
  FProviderReference := FProvider;
  FSettings := TMCPAuthSettings.Defaults(Issuer);
  FVerifier := TPkce.NewVerifier;

  var Key: TBytes;
  SetLength(Key, KeyLength);
  FillChar(Key[0], KeyLength, 3);
  const Keys = TCollections.CreateDictionary<string, TBytes>;
  Keys[KeyId] := Key;
  const Protector = TAesGcmProtector.Create(TKeyRing.Create(KeyId, Keys));

  const Providers = TUpstreamProviders.Create([FProviderReference]);
  const Accounts: ILinkedAccounts = TLinkedAccounts.Create(FStores.Users, FStores.LinkedAccounts, Protector, TAllowAllAccessPolicy.Create, Providers, FClockReference);
  const Registry = TJsonResourceRegistry.FromJson(BuildResourceRegistryJson);

  FServer := TAuthorizationServer.Create(FStores, Registry, Providers, Accounts, TTokenGenerator.Create, FSettings, FClockReference);
  RegisterClient;
end;

procedure TAuthorizationServerTests.TearDown;
begin
  FServer := nil;
  FProviderReference := nil;
  FStores := Default(TStoreSet);
  FClockReference := nil;
end;

function TAuthorizationServerTests.BuildResourceRegistryJson: string;
begin
  const Hash = TTokenHash.Of('service-secret');
  const Entry = '{"resource":"%s","name":"%s","service_id":"%s","service_secret_sha256":"%s",' +
                '"providers":[{"provider":"fake","scopes":["read"]}]}';
  const EntryA = Format(Entry, [ResourceA, 'Resource A', 'service-a', Hash]);
  const EntryB = Format(Entry, [ResourceB, 'Resource B', 'service-b', Hash]);

  Result := Format('{"resources":[%s,%s]}', [EntryA, EntryB]);
end;

procedure TAuthorizationServerTests.RegisterClient;
begin
  var Client := Default(TOAuthClient);
  Client.ClientId     := ClientId;
  Client.ClientName   := ClientName;
  Client.RedirectUris := [RedirectUri];
  Client.CreatedAtUtc := FClock.NowUtc;
  FStores.Clients.Save(Client);
end;

function TAuthorizationServerTests.AuthorizeRequest(const Resource: string): TAuthorizeRequest;
begin
  Result := Default(TAuthorizeRequest);
  Result.ResponseType        := 'code';
  Result.ClientId            := ClientId;
  Result.RedirectUri         := RedirectUri;
  Result.CodeChallenge       := TPkce.ChallengeOf(FVerifier);
  Result.CodeChallengeMethod := 'S256';
  Result.State               := ClientState;
  Result.Scope               := 'mcp';
  Result.Resource            := Resource;
end;

function TAuthorizationServerTests.ObtainCode(const Resource: string): string;
begin
  FServer.BeginAuthorize(AuthorizeRequest(Resource));
  const Completion = FServer.CompleteUpstream(ProviderName, FProvider.LastState, UpstreamCode);
  const Redirect = FServer.Approve(Completion.PendingId, Completion.UserId);

  Result := QueryParam(Redirect, 'code');
end;

function TAuthorizationServerTests.ObtainCodeWithSession(const Resource, UserId: string): string;
begin
  const Start = FServer.BeginAuthorize(AuthorizeRequest(Resource), UserId);
  const Redirect = FServer.Approve(Start.PendingId, UserId);

  Result := QueryParam(Redirect, 'code');
end;

function TAuthorizationServerTests.CodeRequest(const Code: string): TTokenRequest;
begin
  Result := Default(TTokenRequest);
  Result.GrantType    := 'authorization_code';
  Result.Code         := Code;
  Result.RedirectUri  := RedirectUri;
  Result.ClientId     := ClientId;
  Result.CodeVerifier := FVerifier;
end;

function TAuthorizationServerTests.RefreshRequest(const RefreshToken: string): TTokenRequest;
begin
  Result := Default(TTokenRequest);
  Result.GrantType    := 'refresh_token';
  Result.RefreshToken := RefreshToken;
  Result.ClientId     := ClientId;
end;

function TAuthorizationServerTests.ObtainTokens(const Resource: string): TTokenResponse;
begin
  const Code = ObtainCode(Resource);

  Result := FServer.ExchangeToken(CodeRequest(Code));
end;

function TAuthorizationServerTests.ErrorCodeOf(const Action: TProc): string;
begin
  Result := '';
  try
    Action;
  except
    on E: EOAuthError do
      Result := E.ErrorCode;
  end;
end;

function TAuthorizationServerTests.IsTokenKnown(const Token: string): Boolean;
begin
  var Issued: TIssuedToken;
  Result := FStores.Tokens.TryGet(TTokenHash.Of(Token), Issued);
end;

procedure TAuthorizationServerTests.FullCodeFlowIssuesTokensBoundToResource;
begin
  const Tokens = ObtainTokens(ResourceA);

  var Issued: TIssuedToken;
  Assert.IsTrue(FStores.Tokens.TryGet(TTokenHash.Of(Tokens.AccessToken), Issued), 'access token stored by hash');
  Assert.AreEqual(ResourceA, Issued.Resource);
  Assert.AreEqual(ClientId, Issued.ClientId);
  Assert.IsTrue(Issued.Kind = TTokenKind.Access, 'kind');
  Assert.AreEqual('Bearer', Tokens.TokenType);
  Assert.AreEqual(FSettings.AccessTokenSeconds, Tokens.ExpiresIn);
  Assert.AreEqual('mcp', Tokens.Scope);
  Assert.IsNotEmpty(Tokens.RefreshToken);
  Assert.AreEqual(Format('%s/callback/%s', [Issuer, ProviderName]), FProvider.LastRedirectUri);
end;

procedure TAuthorizationServerTests.MissingResourceIsInvalidTarget;
begin
  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.BeginAuthorize(AuthorizeRequest(''));
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidTarget, ErrorCode);
end;

procedure TAuthorizationServerTests.UnknownResourceIsInvalidTarget;
begin
  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.BeginAuthorize(AuthorizeRequest('https://c.example.test/mcp'));
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidTarget, ErrorCode);
end;

procedure TAuthorizationServerTests.WrongVerifierIsInvalidGrant;
begin
  const Code = ObtainCode(ResourceA);
  var Request := CodeRequest(Code);
  Request.CodeVerifier := TPkce.NewVerifier;

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.ExchangeToken(Request);
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidGrant, ErrorCode);
end;

procedure TAuthorizationServerTests.CodeIsSingleUse;
begin
  const Code = ObtainCode(ResourceA);
  FServer.ExchangeToken(CodeRequest(Code));

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.ExchangeToken(CodeRequest(Code));
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidGrant, ErrorCode);
end;

procedure TAuthorizationServerTests.ExpiredCodeIsInvalidGrant;
begin
  const Code = ObtainCode(ResourceA);
  FClock.AdvanceSeconds(FSettings.CodeSeconds + 1);

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.ExchangeToken(CodeRequest(Code));
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidGrant, ErrorCode);
end;

procedure TAuthorizationServerTests.RedirectMismatchAtTokenIsInvalidGrant;
begin
  const Code = ObtainCode(ResourceA);
  var Request := CodeRequest(Code);
  Request.RedirectUri := OtherRedirectUri;

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.ExchangeToken(Request);
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidGrant, ErrorCode);
end;

procedure TAuthorizationServerTests.ResourceMismatchAtTokenIsInvalidTarget;
begin
  const Code = ObtainCode(ResourceA);
  var Request := CodeRequest(Code);
  Request.Resource := ResourceB;

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.ExchangeToken(Request);
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidTarget, ErrorCode);
end;

procedure TAuthorizationServerTests.UnregisteredRedirectRaisesInvalidRedirectUri;
begin
  var Request := AuthorizeRequest(ResourceA);
  Request.RedirectUri := OtherRedirectUri;

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.BeginAuthorize(Request);
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidRedirectUri, ErrorCode);
  Assert.IsEmpty(FProvider.LastState, 'no upstream login started');
end;

procedure TAuthorizationServerTests.UnknownClientRaisesInvalidClient;
begin
  var Request := AuthorizeRequest(ResourceA);
  Request.ClientId := 'unknown-client';

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.BeginAuthorize(Request);
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidClient, ErrorCode);
end;

procedure TAuthorizationServerTests.PlainChallengeMethodIsRejected;
begin
  var Request := AuthorizeRequest(ResourceA);
  Request.CodeChallengeMethod := 'plain';
  Request.CodeChallenge := FVerifier;

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.BeginAuthorize(Request);
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidRequest, ErrorCode);
end;

procedure TAuthorizationServerTests.OtherScopeIsInvalidScope;
begin
  var Request := AuthorizeRequest(ResourceA);
  Request.Scope := 'admin';

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.BeginAuthorize(Request);
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidScope, ErrorCode);
end;

procedure TAuthorizationServerTests.RefreshRotatesAndOldTokenStopsWorking;
begin
  const First = ObtainTokens(ResourceA);

  const Second = FServer.ExchangeToken(RefreshRequest(First.RefreshToken));

  Assert.AreNotEqual(First.RefreshToken, Second.RefreshToken);
  Assert.AreNotEqual(First.AccessToken, Second.AccessToken);

  var Issued: TIssuedToken;
  FStores.Tokens.TryGet(TTokenHash.Of(Second.AccessToken), Issued);
  Assert.AreEqual(ResourceA, Issued.Resource);

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.ExchangeToken(RefreshRequest(First.RefreshToken));
    end);
  Assert.AreEqual(TOAuthErrorCode.InvalidGrant, ErrorCode);
end;

procedure TAuthorizationServerTests.RefreshReuseRevokesFamily;
begin
  const First = ObtainTokens(ResourceA);
  const Second = FServer.ExchangeToken(RefreshRequest(First.RefreshToken));

  const ReuseError = ErrorCodeOf(
    procedure
    begin
      FServer.ExchangeToken(RefreshRequest(First.RefreshToken));
    end);

  const NewestError = ErrorCodeOf(
    procedure
    begin
      FServer.ExchangeToken(RefreshRequest(Second.RefreshToken));
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidGrant, ReuseError, 'reused token');
  Assert.AreEqual(TOAuthErrorCode.InvalidGrant, NewestError, 'newest refresh token after reuse');
  Assert.IsFalse(IsTokenKnown(Second.AccessToken), 'newest access token after reuse');
end;

procedure TAuthorizationServerTests.AccessTokenIsNotAcceptedAsRefreshToken;
begin
  const Tokens = ObtainTokens(ResourceA);

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.ExchangeToken(RefreshRequest(Tokens.AccessToken));
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidGrant, ErrorCode);
  Assert.IsTrue(IsTokenKnown(Tokens.AccessToken), 'access token stays valid');
end;

procedure TAuthorizationServerTests.DenyRedirectsWithAccessDeniedAndState;
begin
  FServer.BeginAuthorize(AuthorizeRequest(ResourceA));
  const Completion = FServer.CompleteUpstream(ProviderName, FProvider.LastState, UpstreamCode);

  const Redirect = FServer.Deny(Completion.PendingId, Completion.UserId);

  Assert.IsTrue(Redirect.StartsWith(Format('%s?', [RedirectUri])), Redirect);
  Assert.AreEqual(TOAuthErrorCode.AccessDenied, QueryParam(Redirect, 'error'));
  Assert.AreEqual(ClientState, QueryParam(Redirect, 'state'));
  Assert.IsEmpty(QueryParam(Redirect, 'code'));
end;

procedure TAuthorizationServerTests.ExistingSessionSkipsUpstreamLogin;
begin
  const Start = FServer.BeginAuthorize(AuthorizeRequest(ResourceA), SessionUser);

  Assert.IsEmpty(Start.UpstreamUrl);
  Assert.IsEmpty(FProvider.LastState, 'no upstream login started');

  const Redirect = FServer.Approve(Start.PendingId, SessionUser);
  const Tokens = FServer.ExchangeToken(CodeRequest(QueryParam(Redirect, 'code')));

  var Issued: TIssuedToken;
  FStores.Tokens.TryGet(TTokenHash.Of(Tokens.AccessToken), Issued);
  Assert.AreEqual(SessionUser, Issued.UserId);
  Assert.AreEqual(ClientState, QueryParam(Redirect, 'state'));
end;

procedure TAuthorizationServerTests.ApproveByOtherUserIsRejected;
begin
  const Start = FServer.BeginAuthorize(AuthorizeRequest(ResourceA), SessionUser);

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.Approve(Start.PendingId, OtherUser);
    end);

  Assert.AreEqual(TOAuthErrorCode.AccessDenied, ErrorCode);

  const Redirect = FServer.Approve(Start.PendingId, SessionUser);
  Assert.IsNotEmpty(QueryParam(Redirect, 'code'), 'the right user can still approve');
end;

procedure TAuthorizationServerTests.DenyByOtherUserIsRejected;
begin
  const Start = FServer.BeginAuthorize(AuthorizeRequest(ResourceA), SessionUser);

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.Deny(Start.PendingId, OtherUser);
    end);

  Assert.AreEqual(TOAuthErrorCode.AccessDenied, ErrorCode);

  const Redirect = FServer.Approve(Start.PendingId, SessionUser);
  Assert.IsNotEmpty(QueryParam(Redirect, 'code'), 'the request is still open for the right user');
end;

procedure TAuthorizationServerTests.UpstreamCallbackIsSingleUse;
begin
  FServer.BeginAuthorize(AuthorizeRequest(ResourceA));
  const State = FProvider.LastState;
  FServer.CompleteUpstream(ProviderName, State, UpstreamCode);

  const ErrorCode = ErrorCodeOf(
    procedure
    begin
      FServer.CompleteUpstream(ProviderName, State, UpstreamCode);
    end);

  Assert.AreEqual(TOAuthErrorCode.InvalidRequest, ErrorCode);
  Assert.AreEqual(1, FProvider.ExchangeCount);
end;

procedure TAuthorizationServerTests.ConsentInfoNamesResource;
begin
  const Start = FServer.BeginAuthorize(AuthorizeRequest(ResourceB), SessionUser);

  const Info = FServer.ConsentInfo(Start.PendingId);

  Assert.AreEqual('Resource B', Info.ResourceName);
  Assert.AreEqual(ClientName, Info.ClientName);
  Assert.AreEqual('localhost', Info.RedirectHost);
end;

procedure TAuthorizationServerTests.LinkAccountLoginLinksToGivenUser;
begin
  FServer.BeginLogin(ProviderName, TLoginPurpose.Portal);
  const Login = FServer.CompleteUpstream(ProviderName, FProvider.LastState, UpstreamCode);
  FProvider.SetIdentity('tenant-2', 'object-2', 'Second', 'second@example.test');

  FServer.BeginLogin(ProviderName, TLoginPurpose.LinkAccount, Login.UserId);
  const Link = FServer.CompleteUpstream(ProviderName, FProvider.LastState, UpstreamCode);

  Assert.IsTrue(Link.Purpose = TLoginPurpose.LinkAccount, 'purpose');
  Assert.AreEqual(Login.UserId, Link.UserId);
  Assert.AreEqual(2, FStores.LinkedAccounts.ListForUser(Login.UserId).Count);
end;

procedure TAuthorizationServerTests.RevokeRemovesFamily;
begin
  const Tokens = ObtainTokens(ResourceA);

  FServer.Revoke(Tokens.RefreshToken);
  FServer.Revoke('unknown-token');

  Assert.IsFalse(IsTokenKnown(Tokens.AccessToken), 'access token');
  Assert.IsFalse(IsTokenKnown(Tokens.RefreshToken), 'refresh token');
end;

procedure TAuthorizationServerTests.RevokeFamilyOfOtherUserIsIgnored;
begin
  const Code = ObtainCodeWithSession(ResourceA, SessionUser);
  const Tokens = FServer.ExchangeToken(CodeRequest(Code));
  const Families = FStores.Tokens.ListFamiliesForUser(SessionUser);
  const FamilyId = Families[0].FamilyId;

  FServer.RevokeFamily(OtherUser, FamilyId);

  Assert.IsTrue(IsTokenKnown(Tokens.AccessToken), 'other user cannot revoke');

  FServer.RevokeFamily(SessionUser, FamilyId);

  Assert.IsFalse(IsTokenKnown(Tokens.AccessToken), 'owner can revoke');
end;

end.
