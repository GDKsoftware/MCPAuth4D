unit MCPAuth.Web.ErrorLog;

interface

uses
  System.SysUtils;

type
  TWebErrorLog = class
  public
    // Writes the class name and the request path, nothing else: the message, query, headers, cookies and body
    // of a failed request can hold tokens, codes or addresses.
    class procedure Unexpected(const Error: Exception; const Path: string); static;
  end;

implementation

uses
  MCPServer.Logger;

const
  UnexpectedErrorFormat = 'Unexpected %s while handling %s';

{ TWebErrorLog }

class procedure TWebErrorLog.Unexpected(const Error: Exception; const Path: string);
begin
  TLogger.Error(UnexpectedErrorFormat, [Error.ClassName, TLogger.ExternalText(Path)]);
end;

end.
