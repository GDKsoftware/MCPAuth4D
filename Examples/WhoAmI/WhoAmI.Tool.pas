unit WhoAmI.Tool;

interface

uses
  System.Rtti,
  System.JSON,
  MCPServer.Types,
  MCPServer.Tool.Base,
  MCPAuth.Client.UpstreamAccounts.Interfaces,
  WhoAmI.Tool.Params;

type
  // Shows who called: the user id from the token, the upstream accounts the user linked, and whether an
  // upstream access token can be obtained for the first account. It reports only the length of that token.
  TWhoAmITool = class(TMCPToolBase<TWhoAmIParams>)
  private
    FAccounts: IUpstreamAccounts;
    FAccountPageUrl: string;

    function AccountsToJson(const Accounts: TArray<TRemoteAccount>): TJSONArray;
    function FirstAccountTokenToJson(const UserId: string; const Accounts: TArray<TRemoteAccount>): TJSONObject;

  protected
    function ExecuteWithContext(const Params: TWhoAmIParams; const Context: IMCPRequestContext): TValue; override;

  public
    constructor Create(const Accounts: IUpstreamAccounts; const AccountPageUrl: string); reintroduce;
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Client.UpstreamAccounts.Exceptions;

const
  ToolName = 'whoami';
  ToolDescription = 'Shows the signed-in user, the linked upstream accounts and whether an upstream token is available';

{ TWhoAmITool }

constructor TWhoAmITool.Create(const Accounts: IUpstreamAccounts; const AccountPageUrl: string);
begin
  inherited Create;

  FName := ToolName;
  FDescription := ToolDescription;
  FAccounts := Accounts;
  FAccountPageUrl := AccountPageUrl;
  MarkReadOnly;
end;

function TWhoAmITool.ExecuteWithContext(const Params: TWhoAmIParams; const Context: IMCPRequestContext): TValue;
begin
  const UserId = Context.GetPrincipal;
  const Accounts = FAccounts.ListForUser(UserId);

  const Answer = TJSONObject.Create;
  try
    Answer.AddPair('user_id', UserId);
    Answer.AddPair('accounts', AccountsToJson(Accounts));
    Answer.AddPair('first_account_token', FirstAccountTokenToJson(UserId, Accounts));
    Answer.AddPair('account_page', FAccountPageUrl);
    Result := Answer.Format;
  finally
    Answer.Free;
  end;
end;

function TWhoAmITool.AccountsToJson(const Accounts: TArray<TRemoteAccount>): TJSONArray;
begin
  Result := TJSONArray.Create;
  for var Account in Accounts do
  begin
    const Item = TJSONObject.Create;
    Item.AddPair('key', Account.Key);
    Item.AddPair('provider', Account.Provider);
    Item.AddPair('display_name', Account.DisplayName);
    Item.AddPair('user_name', Account.UserName);
    Item.AddPair('needs_reconnect', TJSONBool.Create(Account.NeedsReconnect));
    Result.AddElement(Item);
  end;
end;

function TWhoAmITool.FirstAccountTokenToJson(const UserId: string; const Accounts: TArray<TRemoteAccount>): TJSONObject;
begin
  Result := TJSONObject.Create;

  const HasAccount = (Length(Accounts) > 0);
  if not HasAccount then
  begin
    Result.AddPair('status', 'no_account');
    Exit;
  end;

  try
    const Token = FAccounts.GetAccessToken(UserId, Accounts[0].Key);
    // Never the token itself: this output ends up in a chat transcript.
    Result.AddPair('status', 'ok');
    Result.AddPair('token_length', TJSONNumber.Create(Token.Length));
  except
    on E: EUpstreamAccountNeedsReconnect do
    begin
      Result.AddPair('status', 'reconnect_required');
      Result.AddPair('reason', E.Reason);
    end;
    on E: EUpstreamAccountsError do
      Result.AddPair('status', E.ClassName);
  end;
end;

end.
