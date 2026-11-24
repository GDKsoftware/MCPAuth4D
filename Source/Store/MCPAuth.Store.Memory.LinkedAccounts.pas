unit MCPAuth.Store.Memory.LinkedAccounts;

interface

uses
  System.SyncObjs,
  Spring.Collections,
  MCPAuth.Identity.Types,
  MCPAuth.Identity.Interfaces;

type
  TMemoryLinkedAccountRepository = class(TInterfacedObject, ILinkedAccountRepository)
  private
    FLock: TCriticalSection;
    FAccounts: IDictionary<string, TLinkedAccount>;

    class function RowKey(const UserId: string; const Key: TAccountKey): string; static;

  public
    constructor Create;
    destructor Destroy; override;

    function TryFind(const UserId: string; const Key: TAccountKey; out Account: TLinkedAccount): Boolean;
    function ListForUser(const UserId: string): IReadOnlyList<TLinkedAccount>;

    procedure Save(const Account: TLinkedAccount);
    procedure Delete(const UserId: string; const Key: TAccountKey);
  end;

implementation

uses
  System.SysUtils;

{ TMemoryLinkedAccountRepository }

class function TMemoryLinkedAccountRepository.RowKey(const UserId: string; const Key: TAccountKey): string;
begin
  Result := Format('%s|%s', [UserId, Key.Value]);
end;

constructor TMemoryLinkedAccountRepository.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FAccounts := TCollections.CreateDictionary<string, TLinkedAccount>;
end;

destructor TMemoryLinkedAccountRepository.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TMemoryLinkedAccountRepository.TryFind(const UserId: string; const Key: TAccountKey; out Account: TLinkedAccount): Boolean;
begin
  FLock.Enter;
  try
    Result := FAccounts.TryGetValue(RowKey(UserId, Key), Account);
  finally
    FLock.Leave;
  end;
end;

function TMemoryLinkedAccountRepository.ListForUser(const UserId: string): IReadOnlyList<TLinkedAccount>;
begin
  const Accounts = TCollections.CreateList<TLinkedAccount>;
  FLock.Enter;
  try
    for var Account in FAccounts.Values do
    begin
      const IsOwnAccount = (Account.UserId = UserId);
      if IsOwnAccount then
      begin
        Accounts.Add(Account);
      end;
    end;
  finally
    FLock.Leave;
  end;
  Result := Accounts.AsReadOnly;
end;

procedure TMemoryLinkedAccountRepository.Save(const Account: TLinkedAccount);
begin
  FLock.Enter;
  try
    FAccounts[RowKey(Account.UserId, Account.Key)] := Account;
  finally
    FLock.Leave;
  end;
end;

procedure TMemoryLinkedAccountRepository.Delete(const UserId: string; const Key: TAccountKey);
begin
  FLock.Enter;
  try
    FAccounts.Remove(RowKey(UserId, Key));
  finally
    FLock.Leave;
  end;
end;

end.
