unit MCPAuth.Identity.Exceptions;

interface

uses
  System.SysUtils;

type
  EAccountLinkedToOtherUser = class(Exception);
  EAccessDenied = class(Exception);
  EUserNotFound = class(Exception);
  ELinkedAccountNotFound = class(Exception);
  ELastAccountCannotBeUnlinked = class(Exception);

  ELinkedAccountNeedsReconnect = class(Exception)
  private
    FReason: string;

  public
    constructor Create(const Reason: string);

    // 'revoked' or 'missing_scopes'
    property Reason: string read FReason;
  end;

implementation

{ ELinkedAccountNeedsReconnect }

constructor ELinkedAccountNeedsReconnect.Create(const Reason: string);
begin
  inherited CreateFmt('The linked account needs to be reconnected (%s)', [Reason]);

  FReason := Reason;
end;

end.
