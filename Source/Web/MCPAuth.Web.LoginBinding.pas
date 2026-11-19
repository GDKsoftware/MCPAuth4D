unit MCPAuth.Web.LoginBinding;

interface

uses
  MCPAuth.OAuth.Settings,
  MCPAuth.Web.Types;

type
  // The login cookie binds an upstream sign-in to the browser that started it. It holds a random value whose hash
  // the pending sign-in keeps, so a callback URL that is handed to another browser cannot complete the sign-in.
  TLoginBindingCookie = record
  public
    class function Issue(const Binding: string; const Settings: TMCPAuthSettings): string; static;
    class function Clear(const Settings: TMCPAuthSettings): string; static;

    // Empty when the browser sent no login cookie.
    class function BindingOf(const Request: TWebRequest; const Settings: TMCPAuthSettings): string; static;
  end;

implementation

uses
  MCPAuth.Web.Cookie;

const
  LoginCookieName = 'mcpauth_login';

{ TLoginBindingCookie }

class function TLoginBindingCookie.Issue(const Binding: string; const Settings: TMCPAuthSettings): string;
begin
  Result := TWebCookie.Build(LoginCookieName, Binding, Settings.PendingSeconds, Settings.SecureCookies);
end;

class function TLoginBindingCookie.Clear(const Settings: TMCPAuthSettings): string;
begin
  Result := TWebCookie.Build(LoginCookieName, '', 0, Settings.SecureCookies);
end;

class function TLoginBindingCookie.BindingOf(const Request: TWebRequest; const Settings: TMCPAuthSettings): string;
begin
  const CookieName = TWebCookie.NameOf(LoginCookieName, Settings.SecureCookies);
  if not Request.TryGetCookie(CookieName, Result) then
    Result := '';
end;

end.
