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

  public
    constructor Create;
    destructor Destroy; override;

    function TryFind(const Key: TAccountKey; out Account: TLinkedAccount): Boolean;
    function ListForUser(const UserId: string): IReadOnlyList<TLinkedAccount>;

    procedure Save(const Account: TLinkedAccount);
    procedure Delete(const UserId: string; const Key: TAccountKey);
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Identity.Exceptions;

{ TMemoryLinkedAccountRepository }

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

function TMemoryLinkedAccountRepository.TryFind(const Key: TAccountKey; out Account: TLinkedAccount): Boolean;
begin
  FLock.Enter;
  try
    Result := FAccounts.TryGetValue(Key.Value, Account);
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
    var Existing: TLinkedAccount;
    const IsKnown = FAccounts.TryGetValue(Account.Key.Value, Existing);
    const IsLinkedToOtherUser = (IsKnown and (Existing.UserId <> Account.UserId));
    if IsLinkedToOtherUser then
    begin
      raise EAccountLinkedToOtherUser.Create('The account is already linked to another user');
    end;

    FAccounts[Account.Key.Value] := Account;
  finally
    FLock.Leave;
  end;
end;

procedure TMemoryLinkedAccountRepository.Delete(const UserId: string; const Key: TAccountKey);
begin
  FLock.Enter;
  try
    var Existing: TLinkedAccount;
    const IsKnown = FAccounts.TryGetValue(Key.Value, Existing);
    const IsOwnAccount = (IsKnown and (Existing.UserId = UserId));
    if IsOwnAccount then
    begin
      FAccounts.Remove(Key.Value);
    end;
  finally
    FLock.Leave;
  end;
end;

end.
