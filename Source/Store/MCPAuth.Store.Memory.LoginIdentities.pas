unit MCPAuth.Store.Memory.LoginIdentities;

interface

uses
  System.SyncObjs,
  Spring.Collections,
  MCPAuth.Identity.Types,
  MCPAuth.Identity.Interfaces;

type
  TMemoryLoginIdentityRepository = class(TInterfacedObject, ILoginIdentityRepository)
  private
    FLock: TCriticalSection;
    FIdentities: IDictionary<string, TLoginIdentity>;

  public
    constructor Create;
    destructor Destroy; override;

    function TryFind(const Key: TAccountKey; out Identity: TLoginIdentity): Boolean;
    function ListForUser(const UserId: string): IReadOnlyList<TLoginIdentity>;

    procedure Save(const Identity: TLoginIdentity);
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  MCPAuth.Identity.Exceptions;

{ TMemoryLoginIdentityRepository }

constructor TMemoryLoginIdentityRepository.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FIdentities := TCollections.CreateDictionary<string, TLoginIdentity>;
end;

destructor TMemoryLoginIdentityRepository.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TMemoryLoginIdentityRepository.TryFind(const Key: TAccountKey; out Identity: TLoginIdentity): Boolean;
begin
  FLock.Enter;
  try
    Result := FIdentities.TryGetValue(Key.Value, Identity);
  finally
    FLock.Leave;
  end;
end;

function TMemoryLoginIdentityRepository.ListForUser(const UserId: string): IReadOnlyList<TLoginIdentity>;
begin
  const Identities = TCollections.CreateList<TLoginIdentity>;
  FLock.Enter;
  try
    for var Identity in FIdentities.Values do
    begin
      const IsOwnIdentity = (Identity.UserId = UserId);
      if IsOwnIdentity then
      begin
        Identities.Add(Identity);
      end;
    end;
  finally
    FLock.Leave;
  end;

  Identities.Sort(
    function(const Left, Right: TLoginIdentity): Integer
    begin
      Result := CompareDateTime(Left.CreatedAtUtc, Right.CreatedAtUtc);
    end);
  Result := Identities.AsReadOnly;
end;

procedure TMemoryLoginIdentityRepository.Save(const Identity: TLoginIdentity);
begin
  FLock.Enter;
  try
    var Existing: TLoginIdentity;
    const IsKnown = FIdentities.TryGetValue(Identity.Key.Value, Existing);
    const IsOtherUsersIdentity = (IsKnown and (Existing.UserId <> Identity.UserId));
    if IsOtherUsersIdentity then
    begin
      raise ELoginIdentityTaken.Create('The account is already the login identity of another user');
    end;

    var Saved := Identity;
    if IsKnown then
    begin
      Saved.CreatedAtUtc := Existing.CreatedAtUtc;
    end;
    FIdentities[Identity.Key.Value] := Saved;
  finally
    FLock.Leave;
  end;
end;

end.
