unit MCPAuth.Web.Types;

interface

type
  TWebSession = record
    IdHash: string;
    UserId: string;
    CsrfToken: string;
    ExpiresAtUtc: TDateTime;
  end;

implementation

end.
