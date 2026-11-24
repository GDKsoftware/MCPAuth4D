unit MCPAuth.Store.Interfaces;

interface

uses
  MCPAuth.Web.Types,
  MCPAuth.Identity.Interfaces,
  MCPAuth.OAuth.Interfaces;

type
  ISessionStore = interface
    ['{E5170A3B-9C48-4D62-B8F1-6A2D0C94E7B3}']
    procedure Put(const Session: TWebSession);
    function TryGet(const IdHash: string; out Session: TWebSession): Boolean;
    procedure Remove(const IdHash: string);
    function DeleteExpired(const NowUtc: TDateTime): Integer;
  end;

  TStoreSet = record
    Users: IUserRepository;
    LoginIdentities: ILoginIdentityRepository;
    LinkedAccounts: ILinkedAccountRepository;
    Clients: IClientRepository;
    Pending: IPendingAuthorizationStore;
    Grants: IGrantStore;
    Tokens: ITokenRepository;
    Sessions: ISessionStore;
  end;

implementation

end.
