unit MCPAuth.Store.Memory.Grants;

interface

uses
  System.SyncObjs,
  Spring.Collections,
  MCPAuth.Clock.Interfaces,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces;

type
  TMemoryGrantStore = class(TInterfacedObject, IGrantStore)
  private
    FClock: IClock;
    FLock: TCriticalSection;
    FGrants: IDictionary<string, TAuthorizationGrant>;

  public
    constructor Create(const Clock: IClock);
    destructor Destroy; override;

    procedure Put(const Grant: TAuthorizationGrant);
    function TryTake(const CodeHash: string; out Grant: TAuthorizationGrant): Boolean;
    function DeleteExpired(const NowUtc: TDateTime): Integer;
  end;

implementation

{ TMemoryGrantStore }

constructor TMemoryGrantStore.Create(const Clock: IClock);
begin
  inherited Create;
  FClock := Clock;
  FLock := TCriticalSection.Create;
  FGrants := TCollections.CreateDictionary<string, TAuthorizationGrant>;
end;

destructor TMemoryGrantStore.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure TMemoryGrantStore.Put(const Grant: TAuthorizationGrant);
begin
  FLock.Enter;
  try
    FGrants[Grant.CodeHash] := Grant;
  finally
    FLock.Leave;
  end;
end;

function TMemoryGrantStore.TryTake(const CodeHash: string; out Grant: TAuthorizationGrant): Boolean;
begin
  FLock.Enter;
  try
    const IsFound = FGrants.TryGetValue(CodeHash, Grant);
    if IsFound then
    begin
      FGrants.Remove(CodeHash);
    end;
    Result := (IsFound and (Grant.ExpiresAtUtc > FClock.NowUtc));
  finally
    FLock.Leave;
  end;
end;

function TMemoryGrantStore.DeleteExpired(const NowUtc: TDateTime): Integer;
begin
  FLock.Enter;
  try
    const ExpiredCodes = TCollections.CreateList<string>;
    for var Entry in FGrants do
    begin
      if Entry.Value.ExpiresAtUtc <= NowUtc then
      begin
        ExpiredCodes.Add(Entry.Key);
      end;
    end;

    for var CodeHash in ExpiredCodes do
    begin
      FGrants.Remove(CodeHash);
    end;
    Result := ExpiredCodes.Count;
  finally
    FLock.Leave;
  end;
end;

end.
