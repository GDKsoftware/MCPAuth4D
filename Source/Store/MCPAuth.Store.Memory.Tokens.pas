unit MCPAuth.Store.Memory.Tokens;

interface

uses
  System.SyncObjs,
  Spring.Collections,
  MCPAuth.Clock.Interfaces,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces;

type
  TTokenPredicate = reference to function(const Token: TIssuedToken): Boolean;

  TMemoryTokenRepository = class(TInterfacedObject, ITokenRepository)
  private
    FClock: IClock;
    FLock: TCriticalSection;
    FTokens: IDictionary<string, TIssuedToken>;
    FRevokedFamilies: IDictionary<string, TDateTime>;

    function IsActive(const Token: TIssuedToken): Boolean;
    function IsLive(const Token: TIssuedToken): Boolean;
    procedure RemoveWhere(const IsRemoved: TTokenPredicate);
    procedure ForgetOldRevocations(const NowUtc: TDateTime);
    function HasTokensInFamily(const FamilyId: string): Boolean;

  public
    constructor Create(const Clock: IClock);
    destructor Destroy; override;

    function TryGet(const Hash: string; out Token: TIssuedToken): Boolean;
    procedure Save(const Token: TIssuedToken);
    function TryConsume(const Hash: string; out Token: TIssuedToken): Boolean;

    function IsKnownConsumed(const Hash: string; out FamilyId: string): Boolean;
    procedure DeleteFamily(const FamilyId: string);
    procedure DeleteForUser(const UserId: string);
    function ListFamiliesForUser(const UserId: string): IReadOnlyList<TGrantedFamily>;
    function HasActiveFamily(const UserId, Resource: string): Boolean;
    function DeleteExpired(const NowUtc: TDateTime): Integer;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils;

const
  // A revocation is kept while tokens of the family exist, and at least this long for refreshes still in flight.
  RevocationRetentionDays = 1;

{ TMemoryTokenRepository }

constructor TMemoryTokenRepository.Create(const Clock: IClock);
begin
  inherited Create;
  FClock := Clock;
  FLock := TCriticalSection.Create;
  FTokens := TCollections.CreateDictionary<string, TIssuedToken>;
  FRevokedFamilies := TCollections.CreateDictionary<string, TDateTime>;
end;

destructor TMemoryTokenRepository.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TMemoryTokenRepository.TryGet(const Hash: string; out Token: TIssuedToken): Boolean;
begin
  FLock.Enter;
  try
    const IsFound = FTokens.TryGetValue(Hash, Token);
    Result := (IsFound and IsLive(Token));
  finally
    FLock.Leave;
  end;
end;

procedure TMemoryTokenRepository.Save(const Token: TIssuedToken);
begin
  FLock.Enter;
  try
    FTokens[Token.Hash] := Token;
  finally
    FLock.Leave;
  end;
end;

function TMemoryTokenRepository.TryConsume(const Hash: string; out Token: TIssuedToken): Boolean;
begin
  FLock.Enter;
  try
    const IsFound = FTokens.TryGetValue(Hash, Token);
    const IsConsumable = (IsFound and IsActive(Token));
    if IsConsumable then
    begin
      var Consumed := Token;
      Consumed.Consumed := True;
      FTokens[Hash] := Consumed;
    end;
    Result := IsConsumable;
  finally
    FLock.Leave;
  end;
end;

function TMemoryTokenRepository.IsKnownConsumed(const Hash: string; out FamilyId: string): Boolean;
begin
  FLock.Enter;
  try
    var Token: TIssuedToken;
    const IsFound = FTokens.TryGetValue(Hash, Token);
    Result := (IsFound and Token.Consumed);
    if Result then
    begin
      FamilyId := Token.FamilyId;
    end
    else
    begin
      FamilyId := '';
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TMemoryTokenRepository.DeleteFamily(const FamilyId: string);
begin
  FLock.Enter;
  try
    FRevokedFamilies[FamilyId] := FClock.NowUtc;
    RemoveWhere(
      function(const Token: TIssuedToken): Boolean
      begin
        Result := (Token.FamilyId = FamilyId);
      end);
  finally
    FLock.Leave;
  end;
end;

procedure TMemoryTokenRepository.DeleteForUser(const UserId: string);
begin
  FLock.Enter;
  try
    RemoveWhere(
      function(const Token: TIssuedToken): Boolean
      begin
        Result := (Token.UserId = UserId);
      end);
  finally
    FLock.Leave;
  end;
end;

function TMemoryTokenRepository.ListFamiliesForUser(const UserId: string): IReadOnlyList<TGrantedFamily>;
begin
  const Families = TCollections.CreateDictionary<string, TGrantedFamily>;
  FLock.Enter;
  try
    for var Token in FTokens.Values do
    begin
      const IsOwnActiveToken = ((Token.UserId = UserId) and IsActive(Token));
      if not IsOwnActiveToken then
      begin
        Continue;
      end;

      var Family: TGrantedFamily;
      const IsKnownFamily = Families.TryGetValue(Token.FamilyId, Family);
      const IsOlder = (IsKnownFamily and (Family.CreatedAtUtc <= Token.CreatedAtUtc));
      if not IsOlder then
      begin
        Family.FamilyId := Token.FamilyId;
        Family.UserId := Token.UserId;
        Family.ClientId := Token.ClientId;
        Family.Resource := Token.Resource;
        Family.CreatedAtUtc := Token.CreatedAtUtc;
        Families[Token.FamilyId] := Family;
      end;
    end;
  finally
    FLock.Leave;
  end;
  Result := TCollections.CreateList<TGrantedFamily>(Families.Values).AsReadOnly;
end;

function TMemoryTokenRepository.HasActiveFamily(const UserId, Resource: string): Boolean;
begin
  Result := False;
  FLock.Enter;
  try
    for var Token in FTokens.Values do
    begin
      const IsMatch = ((Token.UserId = UserId) and (Token.Resource = Resource) and IsActive(Token));
      if IsMatch then
      begin
        Exit(True);
      end;
    end;
  finally
    FLock.Leave;
  end;
end;

function TMemoryTokenRepository.DeleteExpired(const NowUtc: TDateTime): Integer;
begin
  FLock.Enter;
  try
    const CountBefore = FTokens.Count;
    RemoveWhere(
      function(const Token: TIssuedToken): Boolean
      begin
        Result := (Token.ExpiresAtUtc <= NowUtc);
      end);
    Result := CountBefore - FTokens.Count;

    ForgetOldRevocations(NowUtc);
  finally
    FLock.Leave;
  end;
end;

function TMemoryTokenRepository.IsActive(const Token: TIssuedToken): Boolean;
begin
  Result := (not Token.Consumed and IsLive(Token));
end;

function TMemoryTokenRepository.IsLive(const Token: TIssuedToken): Boolean;
begin
  // A token of a revoked family is never live, also when a concurrent refresh saved it after the revocation.
  const IsRevoked = FRevokedFamilies.ContainsKey(Token.FamilyId);

  Result := ((Token.ExpiresAtUtc > FClock.NowUtc) and not IsRevoked);
end;

procedure TMemoryTokenRepository.RemoveWhere(const IsRemoved: TTokenPredicate);
begin
  const RemovedHashes = TCollections.CreateList<string>;
  for var Pair in FTokens do
  begin
    if IsRemoved(Pair.Value) then
    begin
      RemovedHashes.Add(Pair.Key);
    end;
  end;

  for var Hash in RemovedHashes do
  begin
    FTokens.Remove(Hash);
  end;
end;

procedure TMemoryTokenRepository.ForgetOldRevocations(const NowUtc: TDateTime);
begin
  const CutoffUtc = IncDay(NowUtc, -RevocationRetentionDays);
  const ForgottenFamilies = TCollections.CreateList<string>;
  for var Revocation in FRevokedFamilies do
  begin
    const IsForgettable = ((Revocation.Value <= CutoffUtc) and not HasTokensInFamily(Revocation.Key));
    if IsForgettable then
    begin
      ForgottenFamilies.Add(Revocation.Key);
    end;
  end;

  for var FamilyId in ForgottenFamilies do
  begin
    FRevokedFamilies.Remove(FamilyId);
  end;
end;

function TMemoryTokenRepository.HasTokensInFamily(const FamilyId: string): Boolean;
begin
  Result := FTokens.Values.Any(
    function(const Token: TIssuedToken): Boolean
    begin
      Result := (Token.FamilyId = FamilyId);
    end);
end;

end.
