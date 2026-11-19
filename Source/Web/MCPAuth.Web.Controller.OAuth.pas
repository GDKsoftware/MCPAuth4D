unit MCPAuth.Web.Controller.OAuth;

interface

uses
  Spring.Collections,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Secret.Interfaces,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Errors,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.OAuth.Settings,
  MCPAuth.OAuth.RedirectPolicy,
  MCPAuth.OAuth.Registration,
  MCPAuth.Web.Types,
  MCPAuth.Web.Router,
  MCPAuth.Web.Session.Interfaces,
  MCPAuth.Web.Page.Interfaces,
  MCPAuth.Web.Page.Models;

type
  // The public OAuth endpoints. The handlers registered on a router refer to this controller,
  // so the controller must outlive that router.
  TOAuthController = class
  private
    FServer: IAuthorizationServer;
    FSessions: IWebSessions;
    FPages: IPageRenderer;
    FSettings: TMCPAuthSettings;
    FPolicy: TRedirectPolicy;
    FRegistration: TClientRegistration;

    class function AuthorizeRequestOf(const Request: TWebRequest): TAuthorizeRequest; static;
    class function IsShownWithoutRedirect(const Error: EOAuthError): Boolean; static;
    class function AuthorizeErrorRedirect(const Request: TAuthorizeRequest; const Error: EOAuthError): TWebResponse; static;
    class function AppendQuery(const Uri: string; const Fields: TArray<TPair<string, string>>): string; static;
    class function ConsentLocation(const PendingId: string): string; static;
    class function TokenRequestOf(const Request: TWebRequest): TTokenRequest; static;
    class function TokenResponseJson(const Tokens: TTokenResponse): string; static;
    class function OAuthError(const Error: EOAuthError): TWebResponse; static;
    class function WithNoStore(const Response: TWebResponse): TWebResponse; static;

    function GuardPage(const Handler: TWebHandler): TWebHandler;
    function GuardJson(const Handler: TWebHandler): TWebHandler;

    function HandleMetadata(const Request: TWebRequest): TWebResponse;
    function HandleRegister(const Request: TWebRequest): TWebResponse;
    function RegisterClient(const Request: TWebRequest): TWebResponse;

    function HandleAuthorize(const Request: TWebRequest): TWebResponse;
    function StartAuthorize(const Request: TWebRequest; const AuthorizeRequest: TAuthorizeRequest): TWebResponse;
    function RedirectToUpstreamLogin(const AuthorizeRequest: TAuthorizeRequest): TWebResponse;

    function HandleCallback(const Request: TWebRequest): TWebResponse;
    function CompleteSignIn(const Request: TWebRequest): TWebResponse;
    function SignedInResponse(const Request: TWebRequest; const Completion: TUpstreamCompletion): TWebResponse;
    function SignedInLocation(const Completion: TUpstreamCompletion): string;

    function HandleConsentPage(const Request: TWebRequest): TWebResponse;
    function ConsentPage(const Session: TWebSession; const PendingId: string): TWebResponse;
    function HandleConsentDecision(const Request: TWebRequest): TWebResponse;
    function Decide(const Session: TWebSession; const Request: TWebRequest): TWebResponse;
    function DecisionErrorPage(const Error: EOAuthError): TWebResponse;

    function HandleToken(const Request: TWebRequest): TWebResponse;
    function ExchangeToken(const Request: TWebRequest): TWebResponse;
    function HandleRevoke(const Request: TWebRequest): TWebResponse;
    function RevokeToken(const Request: TWebRequest): TWebResponse;

    function HandleNotFound(const Request: TWebRequest): TWebResponse;
    function ErrorPage(const StatusCode: Integer; const Message: string): TWebResponse;
    function Page(const StatusCode: Integer; const Template: string; const Model: TPageModel): TWebResponse;

  public
    constructor Create(const Server: IAuthorizationServer;
                       const Clients: IClientRepository;
                       const Sessions: IWebSessions;
                       const Pages: IPageRenderer;
                       const Tokens: ITokenGenerator;
                       const Settings: TMCPAuthSettings;
                       const Clock: IClock);
    destructor Destroy; override;

    procedure Register(const Router: TWebRouter);
  end;

implementation

uses
  System.SysUtils,
  System.JSON,
  System.NetEncoding,
  MCPAuth.Identity.Exceptions,
  MCPAuth.Upstream.Exceptions,
  MCPAuth.Upstream.FormEncoding,
  MCPAuth.OAuth.Metadata,
  MCPAuth.Web.ErrorLog;

const
  StatusOk = 200;
  StatusCreated = 201;
  StatusBadRequest = 400;
  StatusForbidden = 403;
  StatusNotFound = 404;
  StatusConflict = 409;
  StatusInternalServerError = 500;
  StatusBadGateway = 502;

  CallbackPrefix = '/callback/';
  ConsentPath = '/consent';
  AccountPath = '/account';
  ConsentLocationFormat = '/consent?pending=%s';

  ErrorTemplate = 'error.html';
  ConsentTemplate = 'consent.html';
  ErrorTitle = 'Something went wrong';
  ConsentTitle = 'Allow access?';

  ApproveDecision = 'approve';
  DenyDecision = 'deny';
  ServerErrorCode = 'server_error';

  NoStore = 'no-store';

  ServerErrorMessage = 'An unexpected error occurred. Please try again later.';
  NotFoundMessage = 'The page you are looking for does not exist.';
  NoSessionMessage = 'Your session has ended. Start again from your application.';
  CsrfMessage = 'The request could not be verified. Start again from your application.';
  NotYourRequestMessage = 'This request belongs to another sign-in.';
  UnknownDecisionMessage = 'The decision is not valid.';
  UpstreamCancelledMessage = 'The sign-in was cancelled or failed.';
  UpstreamFailedMessage = 'The sign-in with the identity provider failed. Please try again.';
  AccessDeniedMessage = 'Your account has no access to this service.';
  LinkedToOtherUserMessage = 'This account is already linked to another user.';

{ TOAuthController }

class function TOAuthController.AuthorizeRequestOf(const Request: TWebRequest): TAuthorizeRequest;
begin
  Result := Default(TAuthorizeRequest);
  Result.ResponseType        := Request.QueryParam('response_type');
  Result.ClientId            := Request.QueryParam('client_id');
  Result.RedirectUri         := Request.QueryParam('redirect_uri');
  Result.CodeChallenge       := Request.QueryParam('code_challenge');
  Result.CodeChallengeMethod := Request.QueryParam('code_challenge_method');
  Result.State               := Request.QueryParam('state');
  Result.Scope               := Request.QueryParam('scope');
  Result.Resource            := Request.QueryParam('resource');
end;

class function TOAuthController.IsShownWithoutRedirect(const Error: EOAuthError): Boolean;
begin
  // The authorization server checks the client and the redirect URI first (see IAuthorizationServer);
  // any other error means both are valid and may be redirected (RFC 6749 4.1.2.1).
  Result := (Error.ErrorCode = TOAuthErrorCode.InvalidClient) or
            (Error.ErrorCode = TOAuthErrorCode.InvalidRedirectUri);
end;

class function TOAuthController.AuthorizeErrorRedirect(const Request: TAuthorizeRequest; const Error: EOAuthError): TWebResponse;
begin
  var Fields: TArray<TPair<string, string>> := [TPair<string, string>.Create('error', Error.ErrorCode),
                                                TPair<string, string>.Create('error_description', Error.Message)];

  const HasState = not Request.State.IsEmpty;
  if HasState then
    Fields := Fields + [TPair<string, string>.Create('state', Request.State)];

  Result := TWebResponse.Redirect(AppendQuery(Request.RedirectUri, Fields));
end;

class function TOAuthController.AppendQuery(const Uri: string; const Fields: TArray<TPair<string, string>>): string;
begin
  const HasQuery = Uri.Contains('?');
  const Query = TFormEncoding.Encode(Fields);
  if HasQuery then
    Result := Format('%s&%s', [Uri, Query])
  else
    Result := Format('%s?%s', [Uri, Query]);
end;

class function TOAuthController.ConsentLocation(const PendingId: string): string;
begin
  Result := Format(ConsentLocationFormat, [TNetEncoding.URL.EncodeForm(PendingId)]);
end;

class function TOAuthController.TokenRequestOf(const Request: TWebRequest): TTokenRequest;
begin
  Result := Default(TTokenRequest);
  Result.GrantType    := Request.FormField('grant_type');
  Result.Code         := Request.FormField('code');
  Result.RedirectUri  := Request.FormField('redirect_uri');
  Result.ClientId     := Request.FormField('client_id');
  Result.CodeVerifier := Request.FormField('code_verifier');
  Result.RefreshToken := Request.FormField('refresh_token');
  Result.Resource     := Request.FormField('resource');
end;

class function TOAuthController.TokenResponseJson(const Tokens: TTokenResponse): string;
begin
  const Json = TJSONObject.Create;
  try
    Json.AddPair('access_token', Tokens.AccessToken);
    Json.AddPair('token_type', Tokens.TokenType);
    Json.AddPair('expires_in', TJSONNumber.Create(Tokens.ExpiresIn));
    Json.AddPair('refresh_token', Tokens.RefreshToken);
    Json.AddPair('scope', Tokens.Scope);

    Result := Json.ToJSON;
  finally
    Json.Free;
  end;
end;

class function TOAuthController.OAuthError(const Error: EOAuthError): TWebResponse;
begin
  Result := TWebResponse.Error(Error.StatusCode, Error.ErrorCode, Error.Message);
end;

class function TOAuthController.WithNoStore(const Response: TWebResponse): TWebResponse;
begin
  Result := Response;
  Result.AddHeader('Cache-Control', NoStore);
  Result.AddHeader('Pragma', 'no-cache');
end;

constructor TOAuthController.Create(const Server: IAuthorizationServer;
                                    const Clients: IClientRepository;
                                    const Sessions: IWebSessions;
                                    const Pages: IPageRenderer;
                                    const Tokens: ITokenGenerator;
                                    const Settings: TMCPAuthSettings;
                                    const Clock: IClock);
begin
  inherited Create;

  FServer := Server;
  FSessions := Sessions;
  FPages := Pages;
  FSettings := Settings;
  FPolicy := TRedirectPolicy.Create(Settings.ExtraRedirectUris);
  FRegistration := TClientRegistration.Create(Clients, FPolicy, Tokens, Clock);
end;

destructor TOAuthController.Destroy;
begin
  FRegistration.Free;
  FPolicy.Free;
  inherited Destroy;
end;

procedure TOAuthController.Register(const Router: TWebRouter);
begin
  Router.Add('GET', '/.well-known/oauth-authorization-server', GuardJson(HandleMetadata));
  Router.Add('POST', '/register', GuardJson(HandleRegister));
  Router.Add('GET', '/authorize', GuardPage(HandleAuthorize));
  Router.AddPrefix('GET', CallbackPrefix, GuardPage(HandleCallback));
  Router.Add('GET', ConsentPath, GuardPage(HandleConsentPage));
  Router.Add('POST', ConsentPath, GuardPage(HandleConsentDecision));
  Router.Add('POST', '/token', GuardJson(HandleToken));
  Router.Add('POST', '/revoke', GuardJson(HandleRevoke));
  Router.SetNotFound(GuardPage(HandleNotFound));
end;

function TOAuthController.GuardPage(const Handler: TWebHandler): TWebHandler;
begin
  // The last line of defence: no exception detail ever reaches the browser.
  Result :=
    function(const Request: TWebRequest): TWebResponse
    begin
      try
        Result := Handler(Request);
      except
        on E: Exception do
        begin
          TWebErrorLog.Unexpected(E, Request.Path);
          Result := ErrorPage(StatusInternalServerError, ServerErrorMessage);
        end;
      end;
    end;
end;

function TOAuthController.GuardJson(const Handler: TWebHandler): TWebHandler;
begin
  Result :=
    function(const Request: TWebRequest): TWebResponse
    begin
      try
        Result := Handler(Request);
      except
        on E: Exception do
        begin
          TWebErrorLog.Unexpected(E, Request.Path);
          Result := WithNoStore(TWebResponse.Error(StatusInternalServerError, ServerErrorCode, ''));
        end;
      end;
    end;
end;

function TOAuthController.HandleMetadata(const Request: TWebRequest): TWebResponse;
begin
  const Metadata = TAuthorizationServerMetadata.Build(FSettings);
  try
    Result := TWebResponse.Json(StatusOk, Metadata.ToJSON);
  finally
    Metadata.Free;
  end;
end;

function TOAuthController.HandleRegister(const Request: TWebRequest): TWebResponse;
begin
  try
    Result := RegisterClient(Request);
  except
    on E: EOAuthError do
      Result := OAuthError(E);
  end;

  Result := WithNoStore(Result);
end;

function TOAuthController.RegisterClient(const Request: TWebRequest): TWebResponse;
begin
  const RegistrationRequest = Request.JsonBody;
  try
    const Registered = FRegistration.Register(RegistrationRequest);
    try
      Result := TWebResponse.Json(StatusCreated, Registered.ToJSON);
    finally
      Registered.Free;
    end;
  finally
    RegistrationRequest.Free;
  end;
end;

function TOAuthController.HandleAuthorize(const Request: TWebRequest): TWebResponse;
begin
  const AuthorizeRequest = AuthorizeRequestOf(Request);
  try
    Result := StartAuthorize(Request, AuthorizeRequest);
  except
    on E: EOAuthError do
    begin
      if IsShownWithoutRedirect(E) then
        Result := ErrorPage(StatusBadRequest, E.Message)
      else
        Result := AuthorizeErrorRedirect(AuthorizeRequest, E);
    end;
  end;
end;

function TOAuthController.StartAuthorize(const Request: TWebRequest; const AuthorizeRequest: TAuthorizeRequest): TWebResponse;
begin
  var Session: TWebSession;
  const HasSession = FSessions.TryCurrent(Request, Session);
  if not HasSession then
    Exit(RedirectToUpstreamLogin(AuthorizeRequest));

  const Start = FServer.BeginAuthorize(AuthorizeRequest, Session.UserId);
  Result := TWebResponse.Redirect(ConsentLocation(Start.PendingId));
end;

function TOAuthController.RedirectToUpstreamLogin(const AuthorizeRequest: TAuthorizeRequest): TWebResponse;
begin
  const Start = FServer.BeginAuthorize(AuthorizeRequest);

  Result := TWebResponse.Redirect(Start.UpstreamUrl);
end;

function TOAuthController.HandleCallback(const Request: TWebRequest): TWebResponse;
begin
  const IsUpstreamError = not Request.QueryParam('error').IsEmpty;
  if IsUpstreamError then
    Exit(ErrorPage(StatusBadRequest, UpstreamCancelledMessage));

  try
    Result := CompleteSignIn(Request);
  except
    on E: EOAuthError do
      Result := ErrorPage(StatusBadRequest, E.Message);
    on EAccessDenied do
      Result := ErrorPage(StatusForbidden, AccessDeniedMessage);
    on EAccountLinkedToOtherUser do
      Result := ErrorPage(StatusConflict, LinkedToOtherUserMessage);
    on EUpstreamError do
      Result := ErrorPage(StatusBadGateway, UpstreamFailedMessage);
  end;
end;

function TOAuthController.CompleteSignIn(const Request: TWebRequest): TWebResponse;
begin
  const ProviderName = Request.Path.Substring(CallbackPrefix.Length);
  const State = Request.QueryParam('state');
  const Code = Request.QueryParam('code');

  const Completion = FServer.CompleteUpstream(ProviderName, State, Code);

  Result := SignedInResponse(Request, Completion);
end;

function TOAuthController.SignedInResponse(const Request: TWebRequest; const Completion: TUpstreamCompletion): TWebResponse;
begin
  // A sign-in always gets a fresh session id; a session from before the sign-in is ended.
  var EndedCookie: string;
  FSessions.Finish(Request, EndedCookie);

  var Cookie: string;
  FSessions.Start(Completion.UserId, Cookie);

  Result := TWebResponse.Redirect(SignedInLocation(Completion));
  Result.AddCookie(Cookie);
end;

function TOAuthController.SignedInLocation(const Completion: TUpstreamCompletion): string;
begin
  case Completion.Purpose of
    TLoginPurpose.Authorize   : Result := ConsentLocation(Completion.PendingId);
    TLoginPurpose.LinkAccount : Result := AccountPath;
    TLoginPurpose.Portal      : Result := AccountPath;
  else
    raise ENotSupportedException.CreateFmt('Unsupported login purpose: %d', [Ord(Completion.Purpose)]);
  end;
end;

function TOAuthController.HandleConsentPage(const Request: TWebRequest): TWebResponse;
begin
  var Session: TWebSession;
  const HasSession = FSessions.TryCurrent(Request, Session);
  if not HasSession then
    Exit(ErrorPage(StatusForbidden, NoSessionMessage));

  try
    Result := ConsentPage(Session, Request.QueryParam('pending'));
  except
    on E: EOAuthError do
      Result := ErrorPage(StatusBadRequest, E.Message);
  end;
end;

function TOAuthController.ConsentPage(const Session: TWebSession; const PendingId: string): TWebResponse;
begin
  const Info = FServer.ConsentInfo(PendingId);

  const Model = TConsentPageModel.Create;
  try
    Model.Title        := ConsentTitle;
    Model.Csrf         := Session.CsrfToken;
    Model.ClientName   := Info.ClientName;
    Model.RedirectHost := Info.RedirectHost;
    Model.ResourceName := Info.ResourceName;
    Model.PendingId    := PendingId;

    Result := Page(StatusOk, ConsentTemplate, Model);
  finally
    Model.Free;
  end;
end;

function TOAuthController.HandleConsentDecision(const Request: TWebRequest): TWebResponse;
begin
  var Session: TWebSession;
  const HasSession = FSessions.TryCurrent(Request, Session);
  if not HasSession then
    Exit(ErrorPage(StatusForbidden, NoSessionMessage));

  const IsVerified = FSessions.IsValidCsrf(Session, Request.FormField('csrf'));
  if not IsVerified then
    Exit(ErrorPage(StatusForbidden, CsrfMessage));

  try
    Result := Decide(Session, Request);
  except
    on E: EOAuthError do
      Result := DecisionErrorPage(E);
  end;
end;

function TOAuthController.Decide(const Session: TWebSession; const Request: TWebRequest): TWebResponse;
begin
  const PendingId = Request.FormField('pending');
  const Decision = Request.FormField('decision');

  const IsApproved = (Decision = ApproveDecision);
  const IsDenied = (Decision = DenyDecision);
  if not (IsApproved or IsDenied) then
    Exit(ErrorPage(StatusBadRequest, UnknownDecisionMessage));

  // Approve and Deny both check that the pending request belongs to the session user.
  var Location: string;
  if IsApproved then
    Location := FServer.Approve(PendingId, Session.UserId)
  else
    Location := FServer.Deny(PendingId, Session.UserId);

  Result := WithNoStore(TWebResponse.Redirect(Location));
end;

function TOAuthController.DecisionErrorPage(const Error: EOAuthError): TWebResponse;
begin
  const IsOtherUsersRequest = (Error.ErrorCode = TOAuthErrorCode.AccessDenied);
  if IsOtherUsersRequest then
    Result := ErrorPage(StatusForbidden, NotYourRequestMessage)
  else
    Result := ErrorPage(StatusBadRequest, Error.Message);
end;

function TOAuthController.HandleToken(const Request: TWebRequest): TWebResponse;
begin
  try
    Result := ExchangeToken(Request);
  except
    on E: EOAuthError do
      Result := OAuthError(E);
  end;

  Result := WithNoStore(Result);
end;

function TOAuthController.ExchangeToken(const Request: TWebRequest): TWebResponse;
begin
  // Only public clients are registered (token_endpoint_auth_method "none"), so client_id identifies the client.
  const TokenRequest = TokenRequestOf(Request);
  if TokenRequest.ClientId.IsEmpty then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRequest, 'The client_id parameter is required');

  const Tokens = FServer.ExchangeToken(TokenRequest);
  Result := TWebResponse.Json(StatusOk, TokenResponseJson(Tokens));
end;

function TOAuthController.HandleRevoke(const Request: TWebRequest): TWebResponse;
begin
  try
    Result := RevokeToken(Request);
  except
    on E: EOAuthError do
      Result := OAuthError(E);
  end;

  Result := WithNoStore(Result);
end;

function TOAuthController.RevokeToken(const Request: TWebRequest): TWebResponse;
begin
  const Token = Request.FormField('token');
  if Token.IsEmpty then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRequest, 'The token parameter is required');

  // RFC 7009: an unknown or already revoked token is also answered with 200.
  FServer.Revoke(Token);
  Result := TWebResponse.Json(StatusOk, '{}');
end;

function TOAuthController.HandleNotFound(const Request: TWebRequest): TWebResponse;
begin
  Result := ErrorPage(StatusNotFound, NotFoundMessage);
end;

function TOAuthController.ErrorPage(const StatusCode: Integer; const Message: string): TWebResponse;
begin
  const Model = TErrorPageModel.Create;
  try
    Model.Title   := ErrorTitle;
    Model.Message := Message;

    Result := Page(StatusCode, ErrorTemplate, Model);
  finally
    Model.Free;
  end;
end;

function TOAuthController.Page(const StatusCode: Integer; const Template: string; const Model: TPageModel): TWebResponse;
begin
  const Html = FPages.Render(Template, Model);

  // Pages carry session-bound data (CSRF token, pending id) and must never be framed, cached or leak their URL.
  Result := TWebResponse.Html(StatusCode, Html);
  Result.AddHeader('Cache-Control', NoStore);
  Result.AddHeader('X-Frame-Options', 'DENY');
  Result.AddHeader('Content-Security-Policy', 'frame-ancestors ''none''');
  Result.AddHeader('Referrer-Policy', 'no-referrer');
end;

end.
