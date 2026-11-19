unit MCPAuth.Client.UpstreamAccounts.Interfaces;

interface

type
  TRemoteAccount = record
    Key: string;
    Provider: string;
    DisplayName: string;
    UserName: string;
    NeedsReconnect: Boolean;
  end;

  // What an MCP server needs from the auth server about the linked accounts of one user.
  IUpstreamAccounts = interface
    ['{3E7A1C94-5B28-4D6F-A0E1-9C4B7D2F8A53}']
    function ListForUser(const UserId: string): TArray<TRemoteAccount>;

    // Raises EUpstreamAccountNotFound, EUpstreamAccountNeedsReconnect or EUpstreamAccessForbidden
    function GetAccessToken(const UserId, AccountKey: string): string;
  end;

implementation

end.
