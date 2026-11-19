unit MCPAuth.Store.Memory;

interface

uses
  MCPAuth.Clock.Interfaces,
  MCPAuth.Store.Interfaces;

type
  TMemoryStore = class
  public
    class function CreateSet(const Clock: IClock): TStoreSet; static;
  end;

implementation

uses
  MCPAuth.Store.Memory.Users,
  MCPAuth.Store.Memory.LinkedAccounts,
  MCPAuth.Store.Memory.Clients,
  MCPAuth.Store.Memory.PendingAuthorizations,
  MCPAuth.Store.Memory.Grants,
  MCPAuth.Store.Memory.Tokens,
  MCPAuth.Store.Memory.Sessions;

{ TMemoryStore }

class function TMemoryStore.CreateSet(const Clock: IClock): TStoreSet;
begin
  Result.Users := TMemoryUserRepository.Create;
  Result.LinkedAccounts := TMemoryLinkedAccountRepository.Create;
  Result.Clients := TMemoryClientRepository.Create;
  Result.Pending := TMemoryPendingAuthorizationStore.Create(Clock);
  Result.Grants := TMemoryGrantStore.Create(Clock);
  Result.Tokens := TMemoryTokenRepository.Create(Clock);
  Result.Sessions := TMemorySessionStore.Create(Clock);
end;

end.
