unit MCPAuth.Store.Memory.Sessions;

interface

uses
  System.SyncObjs,
  Spring.Collections,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Web.Types,
  MCPAuth.Store.Interfaces;

type
  TMemorySessionStore = class(TInterfacedObject, ISessionStore)
  private
    FClock: IClock;
    FLock: TCriticalSection;
    FSessions: IDictionary<string, TWebSession>;

  public
    constructor Create(const Clock: IClock);
    destructor Destroy; override;

    procedure Put(const Session: TWebSession);
    function TryGet(const IdHash: string; out Session: TWebSession): Boolean;
    procedure Remove(const IdHash: string);
    function DeleteExpired(const NowUtc: TDateTime): Integer;
  end;

implementation

{ TMemorySessionStore }

constructor TMemorySessionStore.Create(const Clock: IClock);
begin
  inherited Create;
  FClock := Clock;
  FLock := TCriticalSection.Create;
  FSessions := TCollections.CreateDictionary<string, TWebSession>;
end;

destructor TMemorySessionStore.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure TMemorySessionStore.Put(const Session: TWebSession);
begin
  FLock.Enter;
  try
    FSessions[Session.IdHash] := Session;
  finally
    FLock.Leave;
  end;
end;

function TMemorySessionStore.TryGet(const IdHash: string; out Session: TWebSession): Boolean;
begin
  FLock.Enter;
  try
    const IsFound = FSessions.TryGetValue(IdHash, Session);
    Result := (IsFound and (Session.ExpiresAtUtc > FClock.NowUtc));
  finally
    FLock.Leave;
  end;
end;

procedure TMemorySessionStore.Remove(const IdHash: string);
begin
  FLock.Enter;
  try
    FSessions.Remove(IdHash);
  finally
    FLock.Leave;
  end;
end;

function TMemorySessionStore.DeleteExpired(const NowUtc: TDateTime): Integer;
begin
  FLock.Enter;
  try
    const ExpiredIds = TCollections.CreateList<string>;
    for var Pair in FSessions do
    begin
      const IsExpired = (Pair.Value.ExpiresAtUtc <= NowUtc);
      if IsExpired then
      begin
        ExpiredIds.Add(Pair.Key);
      end;
    end;

    for var IdHash in ExpiredIds do
    begin
      FSessions.Remove(IdHash);
    end;
    Result := ExpiredIds.Count;
  finally
    FLock.Leave;
  end;
end;

end.
