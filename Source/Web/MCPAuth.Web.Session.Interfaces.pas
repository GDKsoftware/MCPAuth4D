unit MCPAuth.Web.Session.Interfaces;

interface

uses
  MCPAuth.Web.Types;

type
  // Browser sessions of the pages. The cookie holds the session id; the store holds only its hash.
  IWebSessions = interface
    ['{3E9B7A14-6C2F-4D85-A0E3-81F5C6D29B47}']
    function TryCurrent(const Request: TWebRequest; out Session: TWebSession): Boolean;

    // Cookie is the Set-Cookie value that hands the session to the browser.
    function Start(const UserId: string; out Cookie: string): TWebSession;

    // Cookie is the Set-Cookie value that removes the session cookie from the browser.
    procedure Finish(const Request: TWebRequest; out Cookie: string);

    // Compares in constant time; an empty token is never valid.
    function IsValidCsrf(const Session: TWebSession; const Token: string): Boolean;
  end;

implementation

end.
