unit MCPAuth.Client.UpstreamAccounts.Exceptions;

interface

uses
  System.SysUtils;

type
  // Any failure of a call to the auth server. Messages never carry response bodies, tokens or secrets.
  EUpstreamAccountsError = class(Exception);

  EUpstreamAccountNotFound = class(EUpstreamAccountsError);

  EUpstreamAccessForbidden = class(EUpstreamAccountsError);

  EUpstreamAccountNeedsReconnect = class(EUpstreamAccountsError)
  private
    FReason: string;

  public
    constructor Create(const Reason: string);

    // 'revoked' or 'missing_scopes'; empty when the auth server gave none
    property Reason: string read FReason;
  end;

implementation

{ EUpstreamAccountNeedsReconnect }

constructor EUpstreamAccountNeedsReconnect.Create(const Reason: string);
begin
  inherited CreateFmt('The account needs to be reconnected (%s)', [Reason]);

  FReason := Reason;
end;

end.
