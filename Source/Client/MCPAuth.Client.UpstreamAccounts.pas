unit MCPAuth.Client.UpstreamAccounts;

interface

uses
  System.SysUtils,
  System.JSON,
  System.SyncObjs,
  System.Net.HttpClient,
  Spring.Collections,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Client.UpstreamAccounts.Interfaces;

type
  // Calls the internal endpoints of the auth server with the service credentials of one MCP server.
  // Access tokens are cached in memory until a minute before they expire.
  TRemoteUpstreamAccounts = class(TInterfacedObject, IUpstreamAccounts)
  private type
    TCachedToken = record
      AccessToken: string;
      ExpiresAtUtc: TDateTime;
    end;

  private
    FInternalBaseUrl: string;
    FAuthorization: string;
    FClock: IClock;
    FLock: TCriticalSection;
    FTokens: IDictionary<string, TCachedToken>;

    class function BasicAuthorization(const ServiceId, ServiceSecret: string): string; static;
    class function ReasonOf(const Body: string): string; static;
    class function ParseAccounts(const Body: string): TArray<TRemoteAccount>; static;
    class function AccountOf(const Json: TJSONObject): TRemoteAccount; static;
    class function ParseAccessToken(const Body: string; out ExpiresAtUtc: TDateTime): string; static;
    class procedure RaiseForStatus(const Response: IHTTPResponse); static;

    function Post(const Path, Body: string): IHTTPResponse;
    function FetchAccessToken(const UserId, AccountKey: string; out ExpiresAtUtc: TDateTime): string;
    function TryGetCachedToken(const CacheKey: string; out AccessToken: string): Boolean;
    procedure RememberToken(const CacheKey, AccessToken: string; const ExpiresAtUtc: TDateTime);

  public
    const CONNECT_TIMEOUT_MS = 2000;
    const RESPONSE_TIMEOUT_MS = 10000;
    const REFRESH_MARGIN_SECONDS = 60;

    constructor Create(const InternalBaseUrl, ServiceId, ServiceSecret: string; const Clock: IClock = nil);
    destructor Destroy; override;

    function ListForUser(const UserId: string): TArray<TRemoteAccount>;
    function GetAccessToken(const UserId, AccountKey: string): string;
  end;

implementation

uses
  System.Classes,
  System.DateUtils,
  System.NetEncoding,
  System.Net.URLClient,
  MCPAuth.Clock,
  MCPAuth.Client.UpstreamAccounts.Exceptions;

const
  AccountsPath = '/internal/accounts';
  UpstreamTokenPath = '/internal/upstream-token';
  JsonContentType = 'application/json';
  StatusOk = 200;
  StatusUnauthorized = 401;
  StatusForbidden = 403;
  StatusNotFound = 404;
  StatusConflict = 409;
  SlashChar = '/';
  CacheKeySeparator = '|';

{ TRemoteUpstreamAccounts }

constructor TRemoteUpstreamAccounts.Create(const InternalBaseUrl, ServiceId, ServiceSecret: string; const Clock: IClock);
begin
  inherited Create;

  FInternalBaseUrl := InternalBaseUrl.TrimRight([SlashChar]);
  FAuthorization := BasicAuthorization(ServiceId, ServiceSecret);
  FClock := Clock;
  if not Assigned(FClock) then
    FClock := TSystemClock.Create;
  FLock := TCriticalSection.Create;
  FTokens := TCollections.CreateDictionary<string, TCachedToken>;
end;

destructor TRemoteUpstreamAccounts.Destroy;
begin
  FLock.Free;

  inherited;
end;

class function TRemoteUpstreamAccounts.BasicAuthorization(const ServiceId, ServiceSecret: string): string;
begin
  const Credentials = TEncoding.UTF8.GetBytes(Format('%s:%s', [ServiceId, ServiceSecret]));
  Result := 'Basic ' + TNetEncoding.Base64.EncodeBytesToString(Credentials);
end;

class function TRemoteUpstreamAccounts.ReasonOf(const Body: string): string;
begin
  Result := '';

  const Parsed = TJSONObject.ParseJSONValue(Body);
  try
    if Parsed is TJSONObject then
      TJSONObject(Parsed).TryGetValue<string>('reason', Result);
  finally
    Parsed.Free;
  end;
end;

class function TRemoteUpstreamAccounts.AccountOf(const Json: TJSONObject): TRemoteAccount;
begin
  Result := Default(TRemoteAccount);
  Json.TryGetValue<string>('key', Result.Key);
  Json.TryGetValue<string>('provider', Result.Provider);
  Json.TryGetValue<string>('display_name', Result.DisplayName);
  Json.TryGetValue<string>('user_name', Result.UserName);
  Json.TryGetValue<Boolean>('needs_reconnect', Result.NeedsReconnect);
end;

class function TRemoteUpstreamAccounts.ParseAccounts(const Body: string): TArray<TRemoteAccount>;
begin
  const Parsed = TJSONObject.ParseJSONValue(Body);
  try
    const IsList = (Parsed is TJSONArray);
    if not IsList then
      raise EUpstreamAccountsError.Create('The auth server answered with an unexpected account list');

    Result := nil;
    for var Item in TJSONArray(Parsed) do
    begin
      if Item is TJSONObject then
        Result := Result + [AccountOf(TJSONObject(Item))];
    end;
  finally
    Parsed.Free;
  end;
end;

class function TRemoteUpstreamAccounts.ParseAccessToken(const Body: string; out ExpiresAtUtc: TDateTime): string;
begin
  Result := '';
  ExpiresAtUtc := 0;

  const Parsed = TJSONObject.ParseJSONValue(Body);
  try
    var ExpiresAtUnix: Int64 := 0;
    var HasToken := False;
    var HasExpiry := False;
    if Parsed is TJSONObject then
    begin
      HasToken := TJSONObject(Parsed).TryGetValue<string>('access_token', Result);
      HasExpiry := TJSONObject(Parsed).TryGetValue<Int64>('expires_at', ExpiresAtUnix);
    end;

    const IsComplete = (HasToken and HasExpiry);
    if not IsComplete then
      raise EUpstreamAccountsError.Create('The auth server answered with an unexpected token response');

    ExpiresAtUtc := UnixToDateTime(ExpiresAtUnix, True);
  finally
    Parsed.Free;
  end;
end;

class procedure TRemoteUpstreamAccounts.RaiseForStatus(const Response: IHTTPResponse);
begin
  case Response.StatusCode of
    StatusOk           : Exit;
    StatusNotFound     : raise EUpstreamAccountNotFound.Create('The account was not found');
    StatusForbidden    : raise EUpstreamAccessForbidden.Create('The user gave no access to this account for this server');
    StatusConflict     : raise EUpstreamAccountNeedsReconnect.Create(ReasonOf(Response.ContentAsString(TEncoding.UTF8)));
    StatusUnauthorized : raise EUpstreamAccountsError.Create('The auth server rejected the service credentials');
  else
    raise EUpstreamAccountsError.CreateFmt('The auth server answered HTTP %d', [Response.StatusCode]);
  end;
end;

function TRemoteUpstreamAccounts.Post(const Path, Body: string): IHTTPResponse;
begin
  const Client = THTTPClient.Create;
  try
    Client.ConnectionTimeout := CONNECT_TIMEOUT_MS;
    Client.ResponseTimeout := RESPONSE_TIMEOUT_MS;

    const Content = TStringStream.Create(Body, TEncoding.UTF8);
    try
      const Headers: TNetHeaders = [TNetHeader.Create('Authorization', FAuthorization),
                                    TNetHeader.Create('Content-Type', JsonContentType),
                                    TNetHeader.Create('Accept', JsonContentType)];
      try
        Result := Client.Post(FInternalBaseUrl + Path, Content, nil, Headers);
      except
        on ENetException do
          raise EUpstreamAccountsError.Create('The auth server could not be reached');
      end;
    finally
      Content.Free;
    end;
  finally
    Client.Free;
  end;
end;

function TRemoteUpstreamAccounts.ListForUser(const UserId: string): TArray<TRemoteAccount>;
begin
  const Request = TJSONObject.Create;
  try
    Request.AddPair('sub', UserId);

    const Response = Post(AccountsPath, Request.ToJSON);

    RaiseForStatus(Response);
    Result := ParseAccounts(Response.ContentAsString(TEncoding.UTF8));
  finally
    Request.Free;
  end;
end;

function TRemoteUpstreamAccounts.GetAccessToken(const UserId, AccountKey: string): string;
begin
  const CacheKey = UserId + CacheKeySeparator + AccountKey;
  if TryGetCachedToken(CacheKey, Result) then
    Exit;

  var ExpiresAtUtc: TDateTime;
  Result := FetchAccessToken(UserId, AccountKey, ExpiresAtUtc);
  RememberToken(CacheKey, Result, ExpiresAtUtc);
end;

function TRemoteUpstreamAccounts.FetchAccessToken(const UserId, AccountKey: string; out ExpiresAtUtc: TDateTime): string;
begin
  const Request = TJSONObject.Create;
  try
    Request.AddPair('sub', UserId);
    Request.AddPair('account', AccountKey);

    const Response = Post(UpstreamTokenPath, Request.ToJSON);

    RaiseForStatus(Response);
    Result := ParseAccessToken(Response.ContentAsString(TEncoding.UTF8), ExpiresAtUtc);
  finally
    Request.Free;
  end;
end;

function TRemoteUpstreamAccounts.TryGetCachedToken(const CacheKey: string; out AccessToken: string): Boolean;
begin
  AccessToken := '';

  FLock.Enter;
  try
    var Cached: TCachedToken;
    Result := FTokens.TryGetValue(CacheKey, Cached);
    if Result then
    begin
      const UsableUntilUtc = IncSecond(Cached.ExpiresAtUtc, -REFRESH_MARGIN_SECONDS);
      Result := (FClock.NowUtc < UsableUntilUtc);
      if Result then
        AccessToken := Cached.AccessToken
      else
        FTokens.Remove(CacheKey);
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TRemoteUpstreamAccounts.RememberToken(const CacheKey, AccessToken: string; const ExpiresAtUtc: TDateTime);
begin
  var Cached := Default(TCachedToken);
  Cached.AccessToken := AccessToken;
  Cached.ExpiresAtUtc := ExpiresAtUtc;

  FLock.Enter;
  try
    FTokens[CacheKey] := Cached;
  finally
    FLock.Leave;
  end;
end;

end.
