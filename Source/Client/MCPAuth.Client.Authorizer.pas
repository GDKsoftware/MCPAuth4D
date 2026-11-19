unit MCPAuth.Client.Authorizer;

interface

uses
  System.SysUtils,
  System.JSON,
  System.SyncObjs,
  Spring.Collections,
  MCPServer.Authorization,
  MCPAuth.Clock.Interfaces;

type
  // The introspection authorizer of the MCP server library with a cache for positive answers.
  // It sits on TryValidateToken, so audience, expiry and scope checks run on every call, also for cached claims.
  // An entry lives until the earlier of the cache period and the exp of the token.
  TCachingAuthorizer = class(TMCPIntrospectionAuthorizer)
  private type
    TCacheEntry = record
      ClaimsJson: string;
      ExpiresAtUtc: TDateTime;
    end;

  private
    FCacheSeconds: Integer;
    FClock: IClock;
    FLock: TCriticalSection;
    FEntries: IDictionary<string, TCacheEntry>;

    function TryGetCached(const Hash: string; out Claims: TJSONObject): Boolean;
    function TryGetExpiry(const Claims: TJSONObject; out ExpiresAtUtc: TDateTime): Boolean;
    procedure Remember(const Hash: string; const Claims: TJSONObject);
    procedure MakeRoom(const NowUtc: TDateTime);

  protected
    function TryValidateToken(const Token: string; out Claims: TJSONObject): Boolean; override;

  public
    const MAX_ENTRIES = 10000;

    constructor Create(const ExpectedAudience, IntrospectionUrl, ClientId, ClientSecret: string; const CacheSeconds: Integer; const Clock: IClock);
    destructor Destroy; override;
  end;

implementation

uses
  System.DateUtils,
  MCPAuth.Secret.Hash;

const
  ExpiryClaim = 'exp';

{ TCachingAuthorizer }

constructor TCachingAuthorizer.Create(const ExpectedAudience, IntrospectionUrl, ClientId, ClientSecret: string; const CacheSeconds: Integer; const Clock: IClock);
begin
  inherited Create(ExpectedAudience, IntrospectionUrl, ClientId, ClientSecret);

  FCacheSeconds := CacheSeconds;
  FClock := Clock;
  FLock := TCriticalSection.Create;
  FEntries := TCollections.CreateDictionary<string, TCacheEntry>;
end;

destructor TCachingAuthorizer.Destroy;
begin
  FLock.Free;

  inherited;
end;

function TCachingAuthorizer.TryValidateToken(const Token: string; out Claims: TJSONObject): Boolean;
begin
  const Hash = TTokenHash.Of(Token);
  if TryGetCached(Hash, Claims) then
    Exit(True);

  Result := inherited TryValidateToken(Token, Claims);
  if Result then
    Remember(Hash, Claims);
end;

function TCachingAuthorizer.TryGetCached(const Hash: string; out Claims: TJSONObject): Boolean;
begin
  Claims := nil;

  var Entry: TCacheEntry;
  FLock.Enter;
  try
    Result := FEntries.TryGetValue(Hash, Entry);
    if Result and (Entry.ExpiresAtUtc <= FClock.NowUtc) then
    begin
      FEntries.Remove(Hash);
      Result := False;
    end;
  finally
    FLock.Leave;
  end;

  if Result then
    Claims := TJSONObject.ParseJSONValue(Entry.ClaimsJson) as TJSONObject;
  Result := Assigned(Claims);
end;

function TCachingAuthorizer.TryGetExpiry(const Claims: TJSONObject; out ExpiresAtUtc: TDateTime): Boolean;
begin
  var ExpiryUnix: Int64;
  Result := Claims.TryGetValue<Int64>(ExpiryClaim, ExpiryUnix);
  if not Result then
    Exit;

  const TokenExpiresAtUtc = UnixToDateTime(ExpiryUnix, True);
  const CacheExpiresAtUtc = IncSecond(FClock.NowUtc, FCacheSeconds);
  ExpiresAtUtc := TokenExpiresAtUtc;
  if CacheExpiresAtUtc < ExpiresAtUtc then
    ExpiresAtUtc := CacheExpiresAtUtc;
end;

procedure TCachingAuthorizer.Remember(const Hash: string; const Claims: TJSONObject);
begin
  const IsCachingEnabled = (FCacheSeconds > 0);
  if not IsCachingEnabled then
    Exit;

  var Entry := Default(TCacheEntry);
  if not TryGetExpiry(Claims, Entry.ExpiresAtUtc) then
    Exit;

  const NowUtc = FClock.NowUtc;
  const IsStillValid = (Entry.ExpiresAtUtc > NowUtc);
  if not IsStillValid then
    Exit;

  Entry.ClaimsJson := Claims.ToJSON;
  FLock.Enter;
  try
    MakeRoom(NowUtc);
    FEntries[Hash] := Entry;
  finally
    FLock.Leave;
  end;
end;

procedure TCachingAuthorizer.MakeRoom(const NowUtc: TDateTime);
begin
  const IsFull = (FEntries.Count >= MAX_ENTRIES);
  if not IsFull then
    Exit;

  var Expired: TArray<string> := nil;
  for var Pair in FEntries do
  begin
    if Pair.Value.ExpiresAtUtc <= NowUtc then
      Expired := Expired + [Pair.Key];
  end;
  for var Hash in Expired do
  begin
    FEntries.Remove(Hash);
  end;

  const IsStillFull = (FEntries.Count >= MAX_ENTRIES);
  if IsStillFull then
    FEntries.Clear;
end;

end.
