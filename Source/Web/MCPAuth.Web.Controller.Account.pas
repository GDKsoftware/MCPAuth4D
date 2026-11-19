unit MCPAuth.Web.Controller.Account;

interface

uses
  MCPAuth.Resource.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Identity.Types,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.OAuth.Settings,
  MCPAuth.Web.Types,
  MCPAuth.Web.Router,
  MCPAuth.Web.Session.Interfaces,
  MCPAuth.Web.Page.Interfaces,
  MCPAuth.Web.Page.Models;

type
  // The account page of signed-in users and the login, link, reconnect, unlink, revoke and logout actions.
  // The handlers registered on a router refer to this controller, so the controller must outlive that router.
  TAccountController = class
  private type
    TSessionHandler = reference to function(const Request: TWebRequest; const Session: TWebSession): TWebResponse;

  private
    FServer: IAuthorizationServer;
    FAccounts: ILinkedAccounts;
    FRegistry: IResourceRegistry;
    FProviders: IUpstreamProviders;
    FSessions: IWebSessions;
    FPages: IPageRenderer;
    FStores: TStoreSet;
    FSettings: TMCPAuthSettings;

    class function WithNoStore(const Response: TWebResponse): TWebResponse; static;
    class function IsoUtc(const ValueUtc: TDateTime): string; static;

    function GuardPage(const Handler: TWebHandler): TWebHandler;
    function RequireSession(const Handler: TSessionHandler; const MissingSession: TWebHandler): TWebHandler;
    function RequireVerifiedSession(const Handler: TSessionHandler): TWebHandler;
    function RedirectToLogin(const Request: TWebRequest): TWebResponse;
    function NoSessionPage(const Request: TWebRequest): TWebResponse;

    function HandleRoot(const Request: TWebRequest): TWebResponse;
    function HandleLogin(const Request: TWebRequest): TWebResponse;
    function StartPortalLogin(const ProviderName: string): TWebResponse;
    function LoginChoicePage(const ProviderNames: TArray<string>): TWebResponse;

    function ShowAccount(const Request: TWebRequest; const Session: TWebSession): TWebResponse;
    function BuildAccountModel(const Session: TWebSession): TAccountPageModel;
    function BuildAccountRows(const UserId: string): TArray<TAccountRow>;
    function BuildGrantRows(const UserId: string): TArray<TGrantRow>;
    function ResourceNameOf(const ResourceUri: string): string;
    function ClientNameOf(const ClientId: string): string;
    function UserDisplayNameOf(const UserId: string): string;

    function Link(const Request: TWebRequest; const Session: TWebSession): TWebResponse;
    function Reconnect(const Request: TWebRequest; const Session: TWebSession): TWebResponse;
    function StartLinking(const ProviderName: string; const Session: TWebSession): TWebResponse;
    function Unlink(const Request: TWebRequest; const Session: TWebSession): TWebResponse;
    function Revoke(const Request: TWebRequest; const Session: TWebSession): TWebResponse;
    function Logout(const Request: TWebRequest; const Session: TWebSession): TWebResponse;
    function TryFindOwnAccount(const UserId, KeyValue: string; out Account: TLinkedAccount): Boolean;
    function RedirectToUpstream(const Start: TAuthorizeStart): TWebResponse;

    function ErrorPage(const StatusCode: Integer; const Message: string): TWebResponse;
    function Page(const StatusCode: Integer; const Template: string; const Model: TPageModel): TWebResponse;

  public
    constructor Create(const Server: IAuthorizationServer;
                       const Accounts: ILinkedAccounts;
                       const Registry: IResourceRegistry;
                       const Providers: IUpstreamProviders;
                       const Sessions: IWebSessions;
                       const Pages: IPageRenderer;
                       const Stores: TStoreSet;
                       const Settings: TMCPAuthSettings);

    procedure Register(const Router: TWebRouter);
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Identity.Exceptions,
  MCPAuth.OAuth.Errors,
  MCPAuth.Resource.Types,
  MCPAuth.Web.ErrorLog,
  MCPAuth.Web.LoginBinding;

const
  StatusOk = 200;
  StatusBadRequest = 400;
  StatusForbidden = 403;
  StatusNotFound = 404;
  StatusConflict = 409;
  StatusInternalServerError = 500;
  StatusServiceUnavailable = 503;

  AccountPath = '/account';
  LoginPath = '/login';
  CsrfField = 'csrf';
  ProviderField = 'provider';
  KeyField = 'key';
  FamilyField = 'family';

  AccountTemplate = 'account.html';
  LoginTemplate = 'login.html';
  DoneTemplate = 'done.html';
  ErrorTemplate = 'error.html';
  AccountTitle = 'Your account';
  LoginTitle = 'Sign in';
  LoggedOutTitle = 'Logged out';
  ErrorTitle = 'Something went wrong';

  NoStore = 'no-store';
  IsoUtcFormat = 'yyyy-mm-dd"T"hh":"nn":"ss"Z"';

  ServerErrorMessage = 'An unexpected error occurred. Please try again later.';
  NoSessionMessage = 'Your session has ended. Please sign in again.';
  CsrfMessage = 'The request could not be verified. Please go back to your account page and try again.';
  AccountNotFoundMessage = 'The account was not found.';
  LastAccountMessage = 'The last linked account cannot be unlinked, because you could no longer sign in.';
  NoProviderMessage = 'No sign-in provider is configured.';
  LoggedOutMessage = 'You have been logged out.';

{ TAccountController }

class function TAccountController.WithNoStore(const Response: TWebResponse): TWebResponse;
begin
  Result := Response;
  Result.AddHeader('Cache-Control', NoStore);
end;

class function TAccountController.IsoUtc(const ValueUtc: TDateTime): string;
begin
  Result := FormatDateTime(IsoUtcFormat, ValueUtc, TFormatSettings.Invariant);
end;

constructor TAccountController.Create(const Server: IAuthorizationServer;
                                      const Accounts: ILinkedAccounts;
                                      const Registry: IResourceRegistry;
                                      const Providers: IUpstreamProviders;
                                      const Sessions: IWebSessions;
                                      const Pages: IPageRenderer;
                                      const Stores: TStoreSet;
                                      const Settings: TMCPAuthSettings);
begin
  inherited Create;

  FServer := Server;
  FAccounts := Accounts;
  FRegistry := Registry;
  FProviders := Providers;
  FSessions := Sessions;
  FPages := Pages;
  FStores := Stores;
  FSettings := Settings;
end;

procedure TAccountController.Register(const Router: TWebRouter);
begin
  Router.Add('GET', '/', GuardPage(HandleRoot));
  Router.Add('GET', LoginPath, GuardPage(HandleLogin));
  Router.Add('GET', AccountPath, GuardPage(RequireSession(ShowAccount, RedirectToLogin)));
  Router.Add('POST', '/account/link', GuardPage(RequireVerifiedSession(Link)));
  Router.Add('POST', '/account/reconnect', GuardPage(RequireVerifiedSession(Reconnect)));
  Router.Add('POST', '/account/unlink', GuardPage(RequireVerifiedSession(Unlink)));
  Router.Add('POST', '/account/revoke', GuardPage(RequireVerifiedSession(Revoke)));
  Router.Add('POST', '/logout', GuardPage(RequireVerifiedSession(Logout)));
end;

function TAccountController.GuardPage(const Handler: TWebHandler): TWebHandler;
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

function TAccountController.RequireSession(const Handler: TSessionHandler; const MissingSession: TWebHandler): TWebHandler;
begin
  Result :=
    function(const Request: TWebRequest): TWebResponse
    begin
      var Session: TWebSession;
      const HasSession = FSessions.TryCurrent(Request, Session);
      if HasSession then
        Result := Handler(Request, Session)
      else
        Result := MissingSession(Request);
    end;
end;

function TAccountController.RequireVerifiedSession(const Handler: TSessionHandler): TWebHandler;
begin
  const VerifiedHandler: TSessionHandler =
    function(const Request: TWebRequest; const Session: TWebSession): TWebResponse
    begin
      const IsVerified = FSessions.IsValidCsrf(Session, Request.FormField(CsrfField));
      if IsVerified then
        Result := Handler(Request, Session)
      else
        Result := ErrorPage(StatusForbidden, CsrfMessage);
    end;

  Result := RequireSession(VerifiedHandler, NoSessionPage);
end;

function TAccountController.RedirectToLogin(const Request: TWebRequest): TWebResponse;
begin
  Result := WithNoStore(TWebResponse.Redirect(LoginPath));
end;

function TAccountController.NoSessionPage(const Request: TWebRequest): TWebResponse;
begin
  Result := ErrorPage(StatusForbidden, NoSessionMessage);
end;

function TAccountController.HandleRoot(const Request: TWebRequest): TWebResponse;
begin
  Result := TWebResponse.Redirect(AccountPath);
end;

function TAccountController.HandleLogin(const Request: TWebRequest): TWebResponse;
begin
  const RequestedProvider = Request.QueryParam(ProviderField);
  const HasRequestedProvider = not RequestedProvider.IsEmpty;
  if HasRequestedProvider then
    Exit(StartPortalLogin(RequestedProvider));

  const ProviderNames = FProviders.Names;
  case Length(ProviderNames) of
    0 : Result := ErrorPage(StatusServiceUnavailable, NoProviderMessage);
    1 : Result := StartPortalLogin(ProviderNames[0]);
  else
    Result := LoginChoicePage(ProviderNames);
  end;
end;

function TAccountController.StartPortalLogin(const ProviderName: string): TWebResponse;
begin
  try
    const Start = FServer.BeginLogin(ProviderName, TLoginPurpose.Portal);
    Result := RedirectToUpstream(Start);
  except
    on E: EOAuthError do
      Result := ErrorPage(StatusBadRequest, E.Message);
  end;
end;

function TAccountController.LoginChoicePage(const ProviderNames: TArray<string>): TWebResponse;
begin
  const Model = TLoginPageModel.Create;
  try
    Model.Title     := LoginTitle;
    Model.Providers := ProviderNames;

    Result := Page(StatusOk, LoginTemplate, Model);
  finally
    Model.Free;
  end;
end;

function TAccountController.ShowAccount(const Request: TWebRequest; const Session: TWebSession): TWebResponse;
begin
  const Model = BuildAccountModel(Session);
  try
    Result := Page(StatusOk, AccountTemplate, Model);
  finally
    for var Row in Model.Accounts do
      Row.Free;

    for var Row in Model.Grants do
      Row.Free;

    Model.Free;
  end;
end;

function TAccountController.BuildAccountModel(const Session: TWebSession): TAccountPageModel;
begin
  Result := TAccountPageModel.Create;
  Result.Title           := AccountTitle;
  Result.Csrf            := Session.CsrfToken;
  Result.UserDisplayName := UserDisplayNameOf(Session.UserId);
  Result.Providers       := FProviders.Names;
  Result.Accounts        := BuildAccountRows(Session.UserId);
  Result.Grants          := BuildGrantRows(Session.UserId);
end;

function TAccountController.BuildAccountRows(const UserId: string): TArray<TAccountRow>;
begin
  Result := [];
  for var Account in FAccounts.ListForUser(UserId) do
  begin
    const Row = TAccountRow.Create;
    Row.Key            := Account.Key.Value;
    Row.DisplayName    := Account.DisplayName;
    Row.UserName       := Account.UserName;
    Row.NeedsReconnect := Account.NeedsReconnect;
    Result := Result + [Row];
  end;
end;

function TAccountController.BuildGrantRows(const UserId: string): TArray<TGrantRow>;
begin
  Result := [];
  for var Family in FStores.Tokens.ListFamiliesForUser(UserId) do
  begin
    const Row = TGrantRow.Create;
    Row.FamilyId     := Family.FamilyId;
    Row.ResourceName := ResourceNameOf(Family.Resource);
    Row.ClientName   := ClientNameOf(Family.ClientId);
    Row.CreatedAt    := IsoUtc(Family.CreatedAtUtc);
    Result := Result + [Row];
  end;
end;

function TAccountController.ResourceNameOf(const ResourceUri: string): string;
begin
  var Resource: TResourceDefinition;
  const IsKnown = FRegistry.TryGetByUri(ResourceUri, Resource);
  if IsKnown then
    Result := Resource.DisplayName
  else
    Result := ResourceUri;
end;

function TAccountController.ClientNameOf(const ClientId: string): string;
begin
  var Client: TOAuthClient;
  const IsKnown = FStores.Clients.TryGet(ClientId, Client);
  const HasName = (IsKnown and not Client.ClientName.IsEmpty);
  if HasName then
    Result := Client.ClientName
  else
    Result := ClientId;
end;

function TAccountController.UserDisplayNameOf(const UserId: string): string;
begin
  var User: TAuthUser;
  const IsKnown = FStores.Users.TryGet(UserId, User);
  if IsKnown then
    Result := User.DisplayName
  else
    Result := '';
end;

function TAccountController.Link(const Request: TWebRequest; const Session: TWebSession): TWebResponse;
begin
  Result := StartLinking(Request.FormField(ProviderField), Session);
end;

function TAccountController.Reconnect(const Request: TWebRequest; const Session: TWebSession): TWebResponse;
begin
  var Account: TLinkedAccount;
  const IsFound = TryFindOwnAccount(Session.UserId, Request.FormField(KeyField), Account);
  if not IsFound then
    Exit(ErrorPage(StatusNotFound, AccountNotFoundMessage));

  // Signing in again links the account again: the new refresh token replaces the old one and the reconnect flag is cleared.
  Result := StartLinking(Account.Key.Provider, Session);
end;

function TAccountController.StartLinking(const ProviderName: string; const Session: TWebSession): TWebResponse;
begin
  try
    const Start = FServer.BeginLogin(ProviderName, TLoginPurpose.LinkAccount, Session.UserId);
    Result := RedirectToUpstream(Start);
  except
    on E: EOAuthError do
      Result := ErrorPage(StatusBadRequest, E.Message);
  end;
end;

function TAccountController.Unlink(const Request: TWebRequest; const Session: TWebSession): TWebResponse;
begin
  var Account: TLinkedAccount;
  const IsFound = TryFindOwnAccount(Session.UserId, Request.FormField(KeyField), Account);
  if not IsFound then
    Exit(ErrorPage(StatusNotFound, AccountNotFoundMessage));

  try
    FAccounts.Unlink(Session.UserId, Account.Key);
    Result := WithNoStore(TWebResponse.Redirect(AccountPath));
  except
    on ELastAccountCannotBeUnlinked do
      Result := ErrorPage(StatusConflict, LastAccountMessage);
    on ELinkedAccountNotFound do
      Result := ErrorPage(StatusNotFound, AccountNotFoundMessage);
  end;
end;

function TAccountController.Revoke(const Request: TWebRequest; const Session: TWebSession): TWebResponse;
begin
  // A family of another user is ignored by the server, so the account page simply shows the unchanged list.
  FServer.RevokeFamily(Session.UserId, Request.FormField(FamilyField));

  Result := WithNoStore(TWebResponse.Redirect(AccountPath));
end;

function TAccountController.Logout(const Request: TWebRequest; const Session: TWebSession): TWebResponse;
begin
  var Cookie: string;
  FSessions.Finish(Request, Cookie);

  const Model = TDonePageModel.Create;
  try
    Model.Title   := LoggedOutTitle;
    Model.Message := LoggedOutMessage;

    Result := Page(StatusOk, DoneTemplate, Model);
  finally
    Model.Free;
  end;
  Result.AddCookie(Cookie);
end;

function TAccountController.TryFindOwnAccount(const UserId, KeyValue: string; out Account: TLinkedAccount): Boolean;
begin
  Account := Default(TLinkedAccount);
  for var Candidate in FAccounts.ListForUser(UserId) do
  begin
    const IsRequested = SameText(Candidate.Key.Value, KeyValue);
    if IsRequested then
    begin
      Account := Candidate;
      Exit(True);
    end;
  end;

  Result := False;
end;

function TAccountController.RedirectToUpstream(const Start: TAuthorizeStart): TWebResponse;
begin
  Result := WithNoStore(TWebResponse.Redirect(Start.UpstreamUrl));
  Result.AddCookie(TLoginBindingCookie.Issue(Start.BrowserBinding, FSettings));
end;

function TAccountController.ErrorPage(const StatusCode: Integer; const Message: string): TWebResponse;
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

function TAccountController.Page(const StatusCode: Integer; const Template: string; const Model: TPageModel): TWebResponse;
begin
  const Html = FPages.Render(Template, Model);

  // Pages carry session-bound data (CSRF token) and must never be framed, cached or leak their URL.
  Result := TWebResponse.Html(StatusCode, Html);
  Result.AddHeader('Cache-Control', NoStore);
  Result.AddHeader('X-Frame-Options', 'DENY');
  Result.AddHeader('Content-Security-Policy', 'frame-ancestors ''none''');
  Result.AddHeader('Referrer-Policy', 'no-referrer');
end;

end.
