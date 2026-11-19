unit MCPAuth.Store.Memory.PendingAuthorizations;

interface

uses
  System.SyncObjs,
  Spring.Collections,
  MCPAuth.Clock.Interfaces,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces;

type
  TMemoryPendingAuthorizationStore = class(TInterfacedObject, IPendingAuthorizationStore)
  private
    FClock: IClock;
    FLock: TCriticalSection;
    FPending: IDictionary<string, TPendingAuthorization>;

  public
    constructor Create(const Clock: IClock);
    destructor Destroy; override;

    procedure Put(const Pending: TPendingAuthorization);
    function TryGet(const Id: string; out Pending: TPendingAuthorization): Boolean;
    function TryTake(const Id: string; out Pending: TPendingAuthorization): Boolean;
  end;

implementation

{ TMemoryPendingAuthorizationStore }

constructor TMemoryPendingAuthorizationStore.Create(const Clock: IClock);
begin
  inherited Create;
  FClock := Clock;
  FLock := TCriticalSection.Create;
  FPending := TCollections.CreateDictionary<string, TPendingAuthorization>;
end;

destructor TMemoryPendingAuthorizationStore.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure TMemoryPendingAuthorizationStore.Put(const Pending: TPendingAuthorization);
begin
  FLock.Enter;
  try
    FPending[Pending.Id] := Pending;
  finally
    FLock.Leave;
  end;
end;

function TMemoryPendingAuthorizationStore.TryGet(const Id: string; out Pending: TPendingAuthorization): Boolean;
begin
  FLock.Enter;
  try
    const IsFound = FPending.TryGetValue(Id, Pending);
    Result := (IsFound and (Pending.ExpiresAtUtc > FClock.NowUtc));
  finally
    FLock.Leave;
  end;
end;

function TMemoryPendingAuthorizationStore.TryTake(const Id: string; out Pending: TPendingAuthorization): Boolean;
begin
  FLock.Enter;
  try
    const IsFound = FPending.TryGetValue(Id, Pending);
    if IsFound then
    begin
      FPending.Remove(Id);
    end;
    Result := (IsFound and (Pending.ExpiresAtUtc > FClock.NowUtc));
  finally
    FLock.Leave;
  end;
end;

end.
