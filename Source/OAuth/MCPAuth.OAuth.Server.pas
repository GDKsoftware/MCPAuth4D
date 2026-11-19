unit MCPAuth.OAuth.Server;

interface

uses
  Spring.Collections,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Secret.Interfaces,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Resource.Types,
  MCPAuth.Resource.Interfaces,
  MCPAuth.Upstream.Types,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.OAuth.Settings;

type
  // Codes, tokens and upstream state are only stored as their hash.
  // A pending authorization lives from the authorize request until Approve or Deny; after the upstream
  // sign-in it gets a new id and carries the signed-in user, so the upstream callback cannot be replayed.
  TAuthorizationServer = class(TInterfacedObject, IAuthorizationServer)
  private
    FStores: TStoreSet;
    FRegistry: IResourceRegistry;
    FProviders: IUpstreamProviders;
    FAccounts: ILinkedAccounts;
    FTokens: ITokenGenerator;
    FSettings: TMCPAuthSettings;
    FClock: IClock;

    class function NewFamilyId: string; static;
    class function AppendQuery(const Uri: string; const Fields: TArray<TPair<string, string>>): string; static;
    class function HostOf(const Uri: string): string; static;
    class function WithState(const Fields: TArray<TPair<string, string>>; const State: string): TArray<TPair<string, string>>; static;

    function ValidateAuthorizeRequest(const Request: TAuthorizeRequest): TResourceDefinition;
    function GetClient(const ClientId: string): TOAuthClient;
    procedure GuardRedirectUri(const Client: TOAuthClient; const RedirectUri: string);
    procedure GuardResponseType(const ResponseType: string);
    procedure GuardCodeChallenge(const Challenge, Method: string);
    procedure GuardScope(const Scope: string);
    function GetResource(const ResourceUri: string): TResourceDefinition;
    function AuthorizePending(const Request: TAuthorizeRequest): TPendingAuthorization;
    function LoginProviderFor(const Resource: TResourceDefinition): IUpstreamProvider;
    function GetProvider(const Name: string): IUpstreamProvider;
    function StartUpstreamLogin(const Pending: TPendingAuthorization; const Provider: IUpstreamProvider): TAuthorizeStart;
    function CallbackUri(const Provider: IUpstreamProvider): string;
    function PendingExpiry: TDateTime;
    function AwaitConsent(const Pending: TPendingAuthorization): string;

    function TakeUpstreamPending(const ProviderName, State: string): TPendingAuthorization;
    function CompleteAuthorizeLogin(const Pending: TPendingAuthorization; const Tokens: TUpstreamTokens): TUpstreamCompletion;
    function CompleteLinkAccount(const Pending: TPendingAuthorization; const Tokens: TUpstreamTokens): TUpstreamCompletion;
    function CompletePortalLogin(const Pending: TPendingAuthorization; const Tokens: TUpstreamTokens): TUpstreamCompletion;

    function GetPendingForConsent(const PendingId: string): TPendingAuthorization;
    procedure GuardSessionUser(const Pending: TPendingAuthorization; const UserId: string);
    function TakePending(const PendingId: string): TPendingAuthorization;
    function IssueCode(const Pending: TPendingAuthorization): string;

    function ExchangeCode(const Request: TTokenRequest): TTokenResponse;
    function ExchangeRefreshToken(const Request: TTokenRequest): TTokenResponse;
    procedure RejectRefreshToken(const Hash: string);
    procedure GuardResource(const RequestedResource, GrantedResource: string);
    function IssueTokens(const Template: TIssuedToken): TTokenResponse;
    function SaveNewToken(const Template: TIssuedToken; const Kind: TTokenKind; const ExpiresAtUtc: TDateTime): string;

  public
    constructor Create(const Stores: TStoreSet;
                       const Registry: IResourceRegistry;
                       const Providers: IUpstreamProviders;
                       const Accounts: ILinkedAccounts;
                       const Tokens: ITokenGenerator;
                       const Settings: TMCPAuthSettings;
                       const Clock: IClock);

    function BeginAuthorize(const Request: TAuthorizeRequest): TAuthorizeStart; overload;
    function BeginAuthorize(const Request: TAuthorizeRequest; const SessionUserId: string): TAuthorizeStart; overload;

    function BeginLogin(const ProviderName: string; const Purpose: TLoginPurpose; const UserId: string = ''): string;
    function CompleteUpstream(const ProviderName, State, Code: string): TUpstreamCompletion;

    function ConsentInfo(const PendingId: string): TConsentInfo;
    function Approve(const PendingId, UserId: string): string;
    function Deny(const PendingId, UserId: string): string;

    function ExchangeToken(const Request: TTokenRequest): TTokenResponse;

    procedure Revoke(const Token: string);
    procedure RevokeFamily(const UserId, FamilyId: string);
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  System.Net.URLClient,
  MCPAuth.Secret.Hash,
  MCPAuth.OAuth.Errors,
  MCPAuth.OAuth.Pkce,
  MCPAuth.Upstream.FormEncoding;

const
  CodeGrantType = 'authorization_code';
  RefreshGrantType = 'refresh_token';
  CodeResponseType = 'code';
  S256Method = 'S256';
  BearerTokenType = 'Bearer';
  CallbackUriFormat = '%s/callback/%s';

  CodeField = 'code';
  StateField = 'state';
  ErrorField = 'error';

  UnknownPendingMessage = 'The authorization request is unknown or has expired';
  UnknownLoginMessage = 'The sign-in request is unknown or has expired';
  InvalidCodeMessage = 'The authorization code is invalid or has expired';
  InvalidRefreshTokenMessage = 'The refresh token is invalid or has expired';

{ TAuthorizationServer }

class function TAuthorizationServer.NewFamilyId: string;
begin
  const Guid = TGUID.NewGuid;
  const GuidText = Guid.ToString;

  Result := GuidText.Substring(1, GuidText.Length - 2);
end;

class function TAuthorizationServer.AppendQuery(const Uri: string; const Fields: TArray<TPair<string, string>>): string;
begin
  const HasQuery = Uri.Contains('?');
  const Query = TFormEncoding.Encode(Fields);
  if HasQuery then
    Result := Format('%s&%s', [Uri, Query])
  else
    Result := Format('%s?%s', [Uri, Query]);
end;

class function TAuthorizationServer.HostOf(const Uri: string): string;
begin
  const ParsedUri = TURI.Create(Uri);

  Result := ParsedUri.Host;
end;

class function TAuthorizationServer.WithState(const Fields: TArray<TPair<string, string>>; const State: string): TArray<TPair<string, string>>;
begin
  Result := Fields;

  const HasState = not State.IsEmpty;
  if HasState then
    Result := Result + [TPair<string, string>.Create(StateField, State)];
end;

constructor TAuthorizationServer.Create(const Stores: TStoreSet;
                                        const Registry: IResourceRegistry;
                                        const Providers: IUpstreamProviders;
                                        const Accounts: ILinkedAccounts;
                                        const Tokens: ITokenGenerator;
                                        const Settings: TMCPAuthSettings;
                                        const Clock: IClock);
begin
  inherited Create;

  FStores := Stores;
  FRegistry := Registry;
  FProviders := Providers;
  FAccounts := Accounts;
  FTokens := Tokens;
  FSettings := Settings;
  FClock := Clock;
end;

function TAuthorizationServer.BeginAuthorize(const Request: TAuthorizeRequest): TAuthorizeStart;
begin
  const Resource = ValidateAuthorizeRequest(Request);
  const Provider = LoginProviderFor(Resource);
  const Pending = AuthorizePending(Request);

  Result := StartUpstreamLogin(Pending, Provider);
end;

function TAuthorizationServer.BeginAuthorize(const Request: TAuthorizeRequest; const SessionUserId: string): TAuthorizeStart;
begin
  const HasSession = not SessionUserId.IsEmpty;
  if not HasSession then
    Exit(BeginAuthorize(Request));

  ValidateAuthorizeRequest(Request);

  var Pending := AuthorizePending(Request);
  Pending.UserId := SessionUserId;

  Result := Default(TAuthorizeStart);
  Result.PendingId := AwaitConsent(Pending);
end;

function TAuthorizationServer.ValidateAuthorizeRequest(const Request: TAuthorizeRequest): TResourceDefinition;
begin
  // Client and redirect come first: until both are known to be valid, no error may be redirected.
  const Client = GetClient(Request.ClientId);
  GuardRedirectUri(Client, Request.RedirectUri);

  GuardResponseType(Request.ResponseType);
  GuardCodeChallenge(Request.CodeChallenge, Request.CodeChallengeMethod);
  GuardScope(Request.Scope);

  Result := GetResource(Request.Resource);
end;

function TAuthorizationServer.GetClient(const ClientId: string): TOAuthClient;
begin
  const IsKnown = (not ClientId.IsEmpty and FStores.Clients.TryGet(ClientId, Result));
  if not IsKnown then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidClient, 'The client is unknown');
end;

procedure TAuthorizationServer.GuardRedirectUri(const Client: TOAuthClient; const RedirectUri: string);
begin
  for var Registered in Client.RedirectUris do
  begin
    if Registered = RedirectUri then
      Exit;
  end;

  raise EOAuthError.Create(TOAuthErrorCode.InvalidRedirectUri, 'The redirect URI is not registered for this client');
end;

procedure TAuthorizationServer.GuardResponseType(const ResponseType: string);
begin
  const IsCodeResponse = (ResponseType = CodeResponseType);
  if not IsCodeResponse then
    raise EOAuthError.Create(TOAuthErrorCode.UnsupportedResponseType, 'Only response_type "code" is supported');
end;

procedure TAuthorizationServer.GuardCodeChallenge(const Challenge, Method: string);
begin
  const IsS256 = (Method = S256Method);
  if Challenge.IsEmpty or not IsS256 then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRequest, 'A code_challenge with code_challenge_method "S256" is required');
end;

procedure TAuthorizationServer.GuardScope(const Scope: string);
begin
  const IsSupportedScope = (Scope.IsEmpty or (Scope = FSettings.Scope));
  if not IsSupportedScope then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidScope, Format('Only the scope "%s" is supported', [FSettings.Scope]));
end;

function TAuthorizationServer.GetResource(const ResourceUri: string): TResourceDefinition;
begin
  if ResourceUri.IsEmpty then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidTarget, 'The resource parameter is required');

  const IsKnown = FRegistry.TryGetByUri(ResourceUri, Result);
  if not IsKnown then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidTarget, 'The resource is unknown');
end;

function TAuthorizationServer.AuthorizePending(const Request: TAuthorizeRequest): TPendingAuthorization;
begin
  Result := Default(TPendingAuthorization);
  Result.Purpose       := TLoginPurpose.Authorize;
  Result.ClientId      := Request.ClientId;
  Result.RedirectUri   := Request.RedirectUri;
  Result.CodeChallenge := Request.CodeChallenge;
  Result.State         := Request.State;
  Result.Scope         := FSettings.Scope;
  Result.Resource      := Request.Resource;
end;

function TAuthorizationServer.LoginProviderFor(const Resource: TResourceDefinition): IUpstreamProvider;
begin
  for var ResourceProvider in Resource.Providers do
  begin
    if FProviders.TryGet(ResourceProvider.Provider, Result) then
      Exit;
  end;

  // A resource without upstream providers still needs a sign-in; the first configured provider serves it.
  const Names = FProviders.Names;
  const HasProviders = (Length(Names) > 0);
  if not HasProviders then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRequest, 'No upstream sign-in provider is configured');

  Result := GetProvider(Names[0]);
end;

function TAuthorizationServer.GetProvider(const Name: string): IUpstreamProvider;
begin
  const IsKnown = FProviders.TryGet(Name, Result);
  if not IsKnown then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRequest, 'The upstream provider is unknown');
end;

function TAuthorizationServer.StartUpstreamLogin(const Pending: TPendingAuthorization; const Provider: IUpstreamProvider): TAuthorizeStart;
begin
  const State = FTokens.NewToken;
  const Verifier = TPkce.NewVerifier;

  var Stored := Pending;
  Stored.Id               := TTokenHash.Of(State);
  Stored.UpstreamProvider := Provider.Name;
  Stored.UpstreamVerifier := Verifier;
  Stored.ExpiresAtUtc     := PendingExpiry;
  FStores.Pending.Put(Stored);

  const Challenge = TPkce.ChallengeOf(Verifier);
  Result.PendingId := Stored.Id;
  Result.UpstreamUrl := Provider.AuthorizationUrl(State, Challenge, CallbackUri(Provider));
end;

function TAuthorizationServer.CallbackUri(const Provider: IUpstreamProvider): string;
begin
  Result := Format(CallbackUriFormat, [FSettings.Issuer, Provider.Name]);
end;

function TAuthorizationServer.PendingExpiry: TDateTime;
begin
  Result := IncSecond(FClock.NowUtc, FSettings.PendingSeconds);
end;

function TAuthorizationServer.AwaitConsent(const Pending: TPendingAuthorization): string;
begin
  var Waiting := Pending;
  Waiting.Id               := TTokenHash.Of(FTokens.NewToken);
  Waiting.UpstreamProvider := '';
  Waiting.UpstreamVerifier := '';
  Waiting.ExpiresAtUtc     := PendingExpiry;
  FStores.Pending.Put(Waiting);

  Result := Waiting.Id;
end;

function TAuthorizationServer.BeginLogin(const ProviderName: string; const Purpose: TLoginPurpose; const UserId: string): string;
begin
  const IsAuthorize = (Purpose = TLoginPurpose.Authorize);
  if IsAuthorize then
    raise EArgumentException.Create('An authorize sign-in starts with BeginAuthorize');

  const IsLinkWithoutUser = ((Purpose = TLoginPurpose.LinkAccount) and UserId.IsEmpty);
  if IsLinkWithoutUser then
    raise EArgumentException.Create('Linking an account requires the signed-in user');

  const Provider = GetProvider(ProviderName);

  var Pending := Default(TPendingAuthorization);
  Pending.Purpose := Purpose;
  Pending.UserId := UserId;

  const Start = StartUpstreamLogin(Pending, Provider);
  Result := Start.UpstreamUrl;
end;

function TAuthorizationServer.CompleteUpstream(const ProviderName, State, Code: string): TUpstreamCompletion;
begin
  const Pending = TakeUpstreamPending(ProviderName, State);
  const Provider = GetProvider(Pending.UpstreamProvider);
  const Tokens = Provider.ExchangeCode(Code, Pending.UpstreamVerifier, CallbackUri(Provider));

  case Pending.Purpose of
    TLoginPurpose.Authorize   : Result := CompleteAuthorizeLogin(Pending, Tokens);
    TLoginPurpose.LinkAccount : Result := CompleteLinkAccount(Pending, Tokens);
    TLoginPurpose.Portal      : Result := CompletePortalLogin(Pending, Tokens);
  else
    raise ENotSupportedException.CreateFmt('Unsupported login purpose: %d', [Ord(Pending.Purpose)]);
  end;
end;

function TAuthorizationServer.TakeUpstreamPending(const ProviderName, State: string): TPendingAuthorization;
begin
  if State.IsEmpty then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRequest, UnknownLoginMessage);

  const IsKnown = FStores.Pending.TryTake(TTokenHash.Of(State), Result);
  if not IsKnown then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRequest, UnknownLoginMessage);

  // The entry is taken before these checks, so a callback for another provider also ends the sign-in.
  const IsWaitingForUpstream = not Result.UpstreamVerifier.IsEmpty;
  const IsSameProvider = SameText(Result.UpstreamProvider, ProviderName);
  if not (IsWaitingForUpstream and IsSameProvider) then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRequest, UnknownLoginMessage);
end;

function TAuthorizationServer.CompleteAuthorizeLogin(const Pending: TPendingAuthorization; const Tokens: TUpstreamTokens): TUpstreamCompletion;
begin
  const User = FAccounts.ResolveOrCreateUser(Tokens);

  var Waiting := Pending;
  Waiting.UserId := User.Id;

  Result.Purpose := TLoginPurpose.Authorize;
  Result.UserId := User.Id;
  Result.PendingId := AwaitConsent(Waiting);
end;

function TAuthorizationServer.CompleteLinkAccount(const Pending: TPendingAuthorization; const Tokens: TUpstreamTokens): TUpstreamCompletion;
begin
  FAccounts.Link(Pending.UserId, Tokens);

  Result := Default(TUpstreamCompletion);
  Result.Purpose := TLoginPurpose.LinkAccount;
  Result.UserId := Pending.UserId;
end;

function TAuthorizationServer.CompletePortalLogin(const Pending: TPendingAuthorization; const Tokens: TUpstreamTokens): TUpstreamCompletion;
begin
  const User = FAccounts.ResolveOrCreateUser(Tokens);

  Result := Default(TUpstreamCompletion);
  Result.Purpose := Pending.Purpose;
  Result.UserId := User.Id;
end;

function TAuthorizationServer.ConsentInfo(const PendingId: string): TConsentInfo;
begin
  const Pending = GetPendingForConsent(PendingId);
  const Client = GetClient(Pending.ClientId);
  const Resource = GetResource(Pending.Resource);

  Result.ClientName := Client.ClientName;
  if Result.ClientName.IsEmpty then
    Result.ClientName := Client.ClientId;

  Result.RedirectHost := HostOf(Pending.RedirectUri);
  Result.ResourceName := Resource.DisplayName;
end;

function TAuthorizationServer.GetPendingForConsent(const PendingId: string): TPendingAuthorization;
begin
  const IsKnown = (not PendingId.IsEmpty and FStores.Pending.TryGet(PendingId, Result));
  const IsAwaitingConsent = (IsKnown and (Result.Purpose = TLoginPurpose.Authorize) and not Result.UserId.IsEmpty);
  if not IsAwaitingConsent then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRequest, UnknownPendingMessage);
end;

function TAuthorizationServer.Approve(const PendingId, UserId: string): string;
begin
  const Pending = GetPendingForConsent(PendingId);
  GuardSessionUser(Pending, UserId);

  const Taken = TakePending(PendingId);
  const Code = IssueCode(Taken);

  const CodeFields: TArray<TPair<string, string>> = [TPair<string, string>.Create(CodeField, Code)];
  Result := AppendQuery(Taken.RedirectUri, WithState(CodeFields, Taken.State));
end;

procedure TAuthorizationServer.GuardSessionUser(const Pending: TPendingAuthorization; const UserId: string);
begin
  const IsSessionUser = (not UserId.IsEmpty and (Pending.UserId = UserId));
  if not IsSessionUser then
    raise EOAuthError.Create(TOAuthErrorCode.AccessDenied, 'Only the signed-in user of this request may decide on it');
end;

function TAuthorizationServer.TakePending(const PendingId: string): TPendingAuthorization;
begin
  const IsTaken = FStores.Pending.TryTake(PendingId, Result);
  if not IsTaken then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRequest, UnknownPendingMessage);
end;

function TAuthorizationServer.IssueCode(const Pending: TPendingAuthorization): string;
begin
  Result := FTokens.NewToken;

  var Grant := Default(TAuthorizationGrant);
  Grant.CodeHash      := TTokenHash.Of(Result);
  Grant.ClientId      := Pending.ClientId;
  Grant.RedirectUri   := Pending.RedirectUri;
  Grant.CodeChallenge := Pending.CodeChallenge;
  Grant.UserId        := Pending.UserId;
  Grant.Scope         := Pending.Scope;
  Grant.Resource      := Pending.Resource;
  Grant.ExpiresAtUtc  := IncSecond(FClock.NowUtc, FSettings.CodeSeconds);
  FStores.Grants.Put(Grant);
end;

function TAuthorizationServer.Deny(const PendingId, UserId: string): string;
begin
  const Pending = GetPendingForConsent(PendingId);
  GuardSessionUser(Pending, UserId);

  const Taken = TakePending(PendingId);

  const ErrorFields: TArray<TPair<string, string>> = [TPair<string, string>.Create(ErrorField, TOAuthErrorCode.AccessDenied)];
  Result := AppendQuery(Taken.RedirectUri, WithState(ErrorFields, Taken.State));
end;

function TAuthorizationServer.ExchangeToken(const Request: TTokenRequest): TTokenResponse;
begin
  const IsCodeGrant = (Request.GrantType = CodeGrantType);
  const IsRefreshGrant = (Request.GrantType = RefreshGrantType);

  if IsCodeGrant then
    Result := ExchangeCode(Request)
  else if IsRefreshGrant then
    Result := ExchangeRefreshToken(Request)
  else
    raise EOAuthError.Create(TOAuthErrorCode.UnsupportedGrantType, 'Only authorization_code and refresh_token are supported');
end;

function TAuthorizationServer.ExchangeCode(const Request: TTokenRequest): TTokenResponse;
begin
  if Request.Code.IsEmpty then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRequest, 'The code parameter is required');

  GetClient(Request.ClientId);

  var Grant: TAuthorizationGrant;
  const IsKnownCode = FStores.Grants.TryTake(TTokenHash.Of(Request.Code), Grant);
  if not IsKnownCode then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidGrant, InvalidCodeMessage);

  const IsSameClient = (Grant.ClientId = Request.ClientId);
  const IsSameRedirect = (Grant.RedirectUri = Request.RedirectUri);
  const IsVerifierValid = TPkce.Verify(Request.CodeVerifier, Grant.CodeChallenge);
  if not (IsSameClient and IsSameRedirect and IsVerifierValid) then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidGrant, InvalidCodeMessage);

  GuardResource(Request.Resource, Grant.Resource);

  var Template := Default(TIssuedToken);
  Template.FamilyId := NewFamilyId;
  Template.UserId   := Grant.UserId;
  Template.ClientId := Grant.ClientId;
  Template.Scope    := Grant.Scope;
  Template.Resource := Grant.Resource;

  Result := IssueTokens(Template);
end;

function TAuthorizationServer.ExchangeRefreshToken(const Request: TTokenRequest): TTokenResponse;
begin
  if Request.RefreshToken.IsEmpty then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRequest, 'The refresh_token parameter is required');

  const Hash = TTokenHash.Of(Request.RefreshToken);

  var Current: TIssuedToken;
  const IsKnown = FStores.Tokens.TryGet(Hash, Current);
  const IsUnused = (IsKnown and not Current.Consumed);
  if not IsUnused then
    RejectRefreshToken(Hash);

  const IsRefreshToken = (Current.Kind = TTokenKind.Refresh);
  const IsSameClient = (Current.ClientId = Request.ClientId);
  if not (IsRefreshToken and IsSameClient) then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidGrant, InvalidRefreshTokenMessage);

  GuardResource(Request.Resource, Current.Resource);

  // TryConsume is the atomic step: of two concurrent exchanges only one wins, the other counts as reuse.
  var Consumed: TIssuedToken;
  const IsConsumed = FStores.Tokens.TryConsume(Hash, Consumed);
  if not IsConsumed then
    RejectRefreshToken(Hash);

  Consumed.Consumed := False;
  Result := IssueTokens(Consumed);
end;

procedure TAuthorizationServer.RejectRefreshToken(const Hash: string);
begin
  // A rotated refresh token that comes back means it leaked: the whole family is revoked.
  var FamilyId: string;
  const IsReused = FStores.Tokens.IsKnownConsumed(Hash, FamilyId);
  if IsReused then
    FStores.Tokens.DeleteFamily(FamilyId);

  raise EOAuthError.Create(TOAuthErrorCode.InvalidGrant, InvalidRefreshTokenMessage);
end;

procedure TAuthorizationServer.GuardResource(const RequestedResource, GrantedResource: string);
begin
  const IsOtherResource = (not RequestedResource.IsEmpty and (RequestedResource <> GrantedResource));
  if IsOtherResource then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidTarget, 'The resource does not match the grant');
end;

function TAuthorizationServer.IssueTokens(const Template: TIssuedToken): TTokenResponse;
begin
  const NowUtc = FClock.NowUtc;
  const AccessExpiry = IncSecond(NowUtc, FSettings.AccessTokenSeconds);
  const RefreshExpiry = IncDay(NowUtc, FSettings.RefreshTokenDays);

  Result := Default(TTokenResponse);
  Result.AccessToken  := SaveNewToken(Template, TTokenKind.Access, AccessExpiry);
  Result.RefreshToken := SaveNewToken(Template, TTokenKind.Refresh, RefreshExpiry);
  Result.TokenType    := BearerTokenType;
  Result.ExpiresIn    := FSettings.AccessTokenSeconds;
  Result.Scope        := Template.Scope;
end;

function TAuthorizationServer.SaveNewToken(const Template: TIssuedToken; const Kind: TTokenKind; const ExpiresAtUtc: TDateTime): string;
begin
  Result := FTokens.NewToken;

  var Token := Template;
  Token.Hash         := TTokenHash.Of(Result);
  Token.Kind         := Kind;
  Token.Consumed     := False;
  Token.CreatedAtUtc := FClock.NowUtc;
  Token.ExpiresAtUtc := ExpiresAtUtc;
  FStores.Tokens.Save(Token);
end;

procedure TAuthorizationServer.Revoke(const Token: string);
begin
  if Token.IsEmpty then
    Exit;

  const Hash = TTokenHash.Of(Token);

  var Issued: TIssuedToken;
  var FamilyId: string;
  if FStores.Tokens.TryGet(Hash, Issued) then
    FStores.Tokens.DeleteFamily(Issued.FamilyId)
  else if FStores.Tokens.IsKnownConsumed(Hash, FamilyId) then
    FStores.Tokens.DeleteFamily(FamilyId);
end;

procedure TAuthorizationServer.RevokeFamily(const UserId, FamilyId: string);
begin
  const Families = FStores.Tokens.ListFamiliesForUser(UserId);
  const IsOwnFamily = Families.Any(
    function(const Family: TGrantedFamily): Boolean
    begin
      Result := (Family.FamilyId = FamilyId);
    end);

  if IsOwnFamily then
    FStores.Tokens.DeleteFamily(FamilyId);
end;

end.
