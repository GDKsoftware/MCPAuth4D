unit MCPAuth.Web.Cookie;

interface

type
  // Builds the cookies of the pages. Secure cookies get the __Host- prefix: the browser then only accepts them
  // with Secure, Path=/ and without Domain, so a sibling subdomain cannot plant or overwrite them.
  TWebCookie = record
  public
    class function NameOf(const BaseName: string; const Secure: Boolean): string; static;
    class function Build(const BaseName, Value: string; const MaxAgeSeconds: Integer; const Secure: Boolean): string; static;
  end;

implementation

uses
  System.SysUtils;

const
  HostPrefixedFormat = '__Host-%s';
  CookieFormat = '%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax%s';
  SecureAttribute = '; Secure';

{ TWebCookie }

class function TWebCookie.NameOf(const BaseName: string; const Secure: Boolean): string;
begin
  if Secure then
    Result := Format(HostPrefixedFormat, [BaseName])
  else
    Result := BaseName;
end;

class function TWebCookie.Build(const BaseName, Value: string; const MaxAgeSeconds: Integer; const Secure: Boolean): string;
begin
  var SecureText := '';
  if Secure then
    SecureText := SecureAttribute;

  Result := Format(CookieFormat, [NameOf(BaseName, Secure), Value, MaxAgeSeconds, SecureText]);
end;

end.
