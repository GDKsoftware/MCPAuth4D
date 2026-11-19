unit MCPAuth.Web.Session;

interface

uses
  MCPAuth.Clock.Interfaces,
  MCPAuth.Secret.Interfaces,
  MCPAuth.OAuth.Settings,
  MCPAuth.Store.Interfaces,
  MCPAuth.Web.Types,
  MCPAuth.Web.Session.Interfaces;

type
  TWebSessions = class(TInterfacedObject, IWebSessions)
  private
    FStore: ISessionStore;
    FTokens: ITokenGenerator;
    FSettings: TMCPAuthSettings;
    FClock: IClock;

    function CookieName: string;
    function BuildCookie(const Value: string; const MaxAgeSeconds: Integer): string;

  public
    constructor Create(const Store: ISessionStore; const Tokens: ITokenGenerator; const Settings: TMCPAuthSettings; const Clock: IClock);

    function TryCurrent(const Request: TWebRequest; out Session: TWebSession): Boolean;
    function Start(const UserId: string; out Cookie: string): TWebSession;
    procedure Finish(const Request: TWebRequest; out Cookie: string);
    function IsValidCsrf(const Session: TWebSession; const Token: string): Boolean;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  MCPAuth.Secret.Hash,
  MCPAuth.Web.Cookie;

const
  SessionCookieName = 'mcpauth_session';
  SecondsPerHour = 3600;

{ TWebSessions }

constructor TWebSessions.Create(const Store: ISessionStore; const Tokens: ITokenGenerator; const Settings: TMCPAuthSettings; const Clock: IClock);
begin
  inherited Create;

  FStore := Store;
  FTokens := Tokens;
  FSettings := Settings;
  FClock := Clock;
end;

function TWebSessions.TryCurrent(const Request: TWebRequest; out Session: TWebSession): Boolean;
begin
  Session := Default(TWebSession);

  var SessionId: string;
  const HasCookie = (Request.TryGetCookie(CookieName, SessionId) and not SessionId.IsEmpty);
  if not HasCookie then
    Exit(False);

  Result := FStore.TryGet(TTokenHash.Of(SessionId), Session);
end;

function TWebSessions.Start(const UserId: string; out Cookie: string): TWebSession;
begin
  const SessionId = FTokens.NewToken;
  const LifetimeSeconds = FSettings.SessionHours * SecondsPerHour;

  Result := Default(TWebSession);
  Result.IdHash       := TTokenHash.Of(SessionId);
  Result.UserId       := UserId;
  Result.CsrfToken    := FTokens.NewToken;
  Result.ExpiresAtUtc := IncSecond(FClock.NowUtc, LifetimeSeconds);
  FStore.Put(Result);

  Cookie := BuildCookie(SessionId, LifetimeSeconds);
end;

procedure TWebSessions.Finish(const Request: TWebRequest; out Cookie: string);
begin
  var SessionId: string;
  const HasCookie = (Request.TryGetCookie(CookieName, SessionId) and not SessionId.IsEmpty);
  if HasCookie then
    FStore.Remove(TTokenHash.Of(SessionId));

  Cookie := BuildCookie('', 0);
end;

function TWebSessions.IsValidCsrf(const Session: TWebSession; const Token: string): Boolean;
begin
  const HasTokens = (not Token.IsEmpty and not Session.CsrfToken.IsEmpty);

  Result := HasTokens and TTokenHash.SameHash(Session.CsrfToken, Token);
end;

function TWebSessions.CookieName: string;
begin
  Result := TWebCookie.NameOf(SessionCookieName, FSettings.SecureCookies);
end;

function TWebSessions.BuildCookie(const Value: string; const MaxAgeSeconds: Integer): string;
begin
  Result := TWebCookie.Build(SessionCookieName, Value, MaxAgeSeconds, FSettings.SecureCookies);
end;

end.
