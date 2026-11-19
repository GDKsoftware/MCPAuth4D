unit MCPAuth.OAuth.Registration;

interface

uses
  System.JSON,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Secret.Interfaces,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.OAuth.RedirectPolicy;

type
  // RFC 7591 dynamic client registration. Only public clients are registered.
  // Raises EOAuthError for invalid input; the HTTP layer maps it to the error response.
  TClientRegistration = class
  private
    FClients: IClientRepository;
    FPolicy: TRedirectPolicy;
    FTokens: ITokenGenerator;
    FClock: IClock;

    class function AsArray(const Value: TJSONValue): TJSONArray; static;

    function ReadRedirectUris(const Request: TJSONObject): TArray<string>;
    function ReadClientName(const Request: TJSONObject): string;
    procedure GuardAuthMethod(const Request: TJSONObject);
    procedure GuardSubset(const Request: TJSONObject; const Name: string; const Supported: array of string);
    function BuildResponse(const ClientId, ClientName: string; const RedirectUris: TArray<string>; const IssuedAt: Int64): TJSONObject;

  public
    constructor Create(const Clients: IClientRepository; const Policy: TRedirectPolicy; const Tokens: ITokenGenerator; const Clock: IClock);

    // The caller owns the returned object; the request stays owned by the caller.
    function Register(const Request: TJSONObject): TJSONObject;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  MCPAuth.OAuth.Errors,
  MCPAuth.OAuth.Types;

const
  MaxClientNameLength = 100;
  MaxRedirectUris = 10;
  MaxRedirectUriLength = 2000;
  PublicClientAuthMethod = 'none';
  CodeGrant = 'authorization_code';
  RefreshGrant = 'refresh_token';
  CodeResponse = 'code';

{ TClientRegistration }

constructor TClientRegistration.Create(const Clients: IClientRepository; const Policy: TRedirectPolicy; const Tokens: ITokenGenerator; const Clock: IClock);
begin
  inherited Create;

  FClients := Clients;
  FPolicy := Policy;
  FTokens := Tokens;
  FClock := Clock;
end;

function TClientRegistration.Register(const Request: TJSONObject): TJSONObject;
begin
  if not Assigned(Request) then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidClientMetadata, 'The registration request must be a JSON object');

  const RedirectUris = ReadRedirectUris(Request);
  GuardAuthMethod(Request);
  GuardSubset(Request, 'grant_types', [CodeGrant, RefreshGrant]);
  GuardSubset(Request, 'response_types', [CodeResponse]);

  var Client := Default(TOAuthClient);
  Client.ClientId := FTokens.NewToken;
  Client.ClientName := ReadClientName(Request);
  Client.RedirectUris := RedirectUris;
  Client.CreatedAtUtc := FClock.NowUtc;
  FClients.Save(Client);

  Result := BuildResponse(Client.ClientId, Client.ClientName, RedirectUris, DateTimeToUnix(Client.CreatedAtUtc, True));
end;

class function TClientRegistration.AsArray(const Value: TJSONValue): TJSONArray;
begin
  if Value is TJSONArray then
    Result := TJSONArray(Value)
  else
    Result := nil;
end;

function TClientRegistration.ReadRedirectUris(const Request: TJSONObject): TArray<string>;
begin
  const Value = Request.GetValue('redirect_uris');
  const Items = AsArray(Value);
  const HasUris = Assigned(Items) and (Items.Count > 0);
  if not HasUris then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRedirectUri, 'redirect_uris must be a non-empty array');

  // Registration is open to anyone, so a single client may not store an unbounded amount of data.
  const HasTooManyUris = (Items.Count > MaxRedirectUris);
  if HasTooManyUris then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidRedirectUri, Format('redirect_uris may hold at most %d URIs', [MaxRedirectUris]));

  Result := nil;
  for var Item in Items do
  begin
    const IsString = (Item is TJSONString);
    const IsTooLong = (IsString and (Item.Value.Length > MaxRedirectUriLength));
    if not IsString or IsTooLong or not FPolicy.IsAllowed(Item.Value) then
      raise EOAuthError.Create(TOAuthErrorCode.InvalidRedirectUri, 'A redirect URI is not allowed');

    Result := Result + [Item.Value];
  end;
end;

function TClientRegistration.ReadClientName(const Request: TJSONObject): string;
begin
  var Name: string;
  if not Request.TryGetValue<string>('client_name', Name) then
    Exit('');

  Result := Name.Substring(0, MaxClientNameLength);
end;

procedure TClientRegistration.GuardAuthMethod(const Request: TJSONObject);
begin
  var Method: string;
  const IsGiven = Request.TryGetValue<string>('token_endpoint_auth_method', Method);
  if IsGiven and (Method <> PublicClientAuthMethod) then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidClientMetadata, 'Only public clients are supported (token_endpoint_auth_method "none")');
end;

procedure TClientRegistration.GuardSubset(const Request: TJSONObject; const Name: string; const Supported: array of string);
begin
  const Value = Request.GetValue(Name);
  if not Assigned(Value) then
    Exit;

  const Items = AsArray(Value);
  if not Assigned(Items) then
    raise EOAuthError.Create(TOAuthErrorCode.InvalidClientMetadata, Format('%s must be an array', [Name]));

  for var Item in Items do
  begin
    var IsSupported := False;
    for var Candidate in Supported do
    begin
      if (Item is TJSONString) and (Item.Value = Candidate) then
        IsSupported := True;
    end;

    if not IsSupported then
      raise EOAuthError.Create(TOAuthErrorCode.InvalidClientMetadata, Format('%s contains an unsupported value', [Name]));
  end;
end;

function TClientRegistration.BuildResponse(const ClientId, ClientName: string; const RedirectUris: TArray<string>; const IssuedAt: Int64): TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('client_id', ClientId);
    Result.AddPair('client_id_issued_at', TJSONNumber.Create(IssuedAt));
    Result.AddPair('client_name', ClientName);

    const Uris = TJSONArray.Create;
    Result.AddPair('redirect_uris', Uris);
    for var Uri in RedirectUris do
      Uris.Add(Uri);

    const Grants = TJSONArray.Create;
    Result.AddPair('grant_types', Grants);
    Grants.Add(CodeGrant);
    Grants.Add(RefreshGrant);

    const ResponseTypes = TJSONArray.Create;
    Result.AddPair('response_types', ResponseTypes);
    ResponseTypes.Add(CodeResponse);

    Result.AddPair('token_endpoint_auth_method', PublicClientAuthMethod);
  except
    Result.Free;
    raise;
  end;
end;

end.
