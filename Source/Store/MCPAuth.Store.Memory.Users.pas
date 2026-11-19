unit MCPAuth.Store.Memory.Users;

interface

uses
  System.SyncObjs,
  Spring.Collections,
  MCPAuth.Identity.Types,
  MCPAuth.Identity.Interfaces;

type
  TMemoryUserRepository = class(TInterfacedObject, IUserRepository)
  private
    FLock: TCriticalSection;
    FUsers: IDictionary<string, TAuthUser>;

  public
    constructor Create;
    destructor Destroy; override;

    function TryGet(const UserId: string; out User: TAuthUser): Boolean;
    procedure Save(const User: TAuthUser);
  end;

implementation

{ TMemoryUserRepository }

constructor TMemoryUserRepository.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FUsers := TCollections.CreateDictionary<string, TAuthUser>;
end;

destructor TMemoryUserRepository.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TMemoryUserRepository.TryGet(const UserId: string; out User: TAuthUser): Boolean;
begin
  FLock.Enter;
  try
    Result := FUsers.TryGetValue(UserId, User);
  finally
    FLock.Leave;
  end;
end;

procedure TMemoryUserRepository.Save(const User: TAuthUser);
begin
  FLock.Enter;
  try
    FUsers[User.Id] := User;
  finally
    FLock.Leave;
  end;
end;

end.
