unit MCPAuth.Store.FireDAC;

interface

uses
  MCPAuth.Clock.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Store.FireDAC.Interfaces;

type
  // Repositories on PostgreSQL. Apply the migrations with TFireDACMigrations before the first use.
  TFireDACStore = class
  public
    class function CreateSet(const Factory: IFireDACConnectionFactory; const Clock: IClock): TStoreSet; static;
  end;

implementation

uses
  MCPAuth.Store.FireDAC.Dialect,
  MCPAuth.Store.FireDAC.Users,
  MCPAuth.Store.FireDAC.LinkedAccounts,
  MCPAuth.Store.FireDAC.Clients,
  MCPAuth.Store.FireDAC.PendingAuthorizations,
  MCPAuth.Store.FireDAC.Grants,
  MCPAuth.Store.FireDAC.Tokens,
  MCPAuth.Store.FireDAC.Sessions;

{ TFireDACStore }

class function TFireDACStore.CreateSet(const Factory: IFireDACConnectionFactory; const Clock: IClock): TStoreSet;
begin
  const Dialect = TSqlDialect.Postgres;

  Result.Users := TFireDACUserRepository.Create(Factory, Dialect);
  Result.LinkedAccounts := TFireDACLinkedAccountRepository.Create(Factory);
  Result.Clients := TFireDACClientRepository.Create(Factory, Dialect);
  Result.Pending := TFireDACPendingAuthorizationStore.Create(Factory, Dialect, Clock);
  Result.Grants := TFireDACGrantStore.Create(Factory, Dialect, Clock);
  Result.Tokens := TFireDACTokenRepository.Create(Factory, Dialect, Clock);
  Result.Sessions := TFireDACSessionStore.Create(Factory, Dialect, Clock);
end;

end.
