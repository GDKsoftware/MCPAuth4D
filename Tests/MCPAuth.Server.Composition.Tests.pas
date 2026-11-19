unit MCPAuth.Server.Composition.Tests;

interface

uses
  DUnitX.TestFramework,
  Spring.Collections,
  MCPAuth.Server.Settings;

type
  [TestFixture]
  TServerCompositionTests = class
  private
    FRegistryPath: string;
    FVariables: IDictionary<string, string>;

    function LoadSettings: TServerSettings;
    procedure WriteRegistry(const Provider: string);
    function StatusOf(const Method, Url: string): Integer;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure ResourceWithInactiveProviderFailsStartup;

    [Test]
    procedure MissingLibraryTemplatesFailStartup;

    [Test]
    procedure StartedServerKeepsInternalEndpointsOffThePublicListener;
  end;

implementation

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.NetEncoding,
  System.NetConsts,
  System.Net.URLClient,
  System.Net.HttpClient,
  MCPAuth.Secret.Hash,
  MCPAuth.Server.Exceptions,
  MCPAuth.Server.Composition;

const
  KeyLength = 32;
  Loopback = '127.0.0.1';
  StatusOk = 200;
  StatusUnauthorized = 401;
  StatusNotFound = 404;

{ TServerCompositionTests }

procedure TServerCompositionTests.Setup;
begin
  FRegistryPath := TPath.Combine(TPath.GetTempPath, Format('mcpauth-registry-%s.json', [TGUID.NewGuid.ToString]));

  var Key: TBytes;
  SetLength(Key, KeyLength);
  FillChar(Key[0], KeyLength, 9);

  FVariables := TCollections.CreateDictionary<string, string>;
  FVariables['MCPAUTH_ISSUER']               := 'http://localhost:8100';
  FVariables['MCPAUTH_REGISTRY']             := FRegistryPath;
  FVariables['MCPAUTH_MASTER_KEY']           := TNetEncoding.Base64.EncodeBytesToString(Key);
  FVariables['MCPAUTH_PUBLIC_PORT']          := '0';
  FVariables['MCPAUTH_INTERNAL_PORT']        := '0';
  FVariables['MCPAUTH_ALLOW_HTTP_RESOURCES'] := '1';
end;

procedure TServerCompositionTests.TearDown;
begin
  if TFile.Exists(FRegistryPath) then
    TFile.Delete(FRegistryPath);
end;

function TServerCompositionTests.LoadSettings: TServerSettings;
begin
  Result := TServerSettings.FromVariables(
    function(const Name: string): string
    begin
      if not FVariables.TryGetValue(Name, Result) then
        Result := '';
    end,
    TPath.GetDirectoryName(ParamStr(0)));
end;

procedure TServerCompositionTests.WriteRegistry(const Provider: string);
begin
  const Entry = '{"resource":"http://localhost:8080/mcp","name":"Who am I","service_id":"whoami","service_secret_sha256":"%s","providers":[{"provider":"%s","scopes":["User.Read"]}]}';
  const Json = Format('{"resources":[%s]}', [Format(Entry, [TTokenHash.Of('service-secret'), Provider])]);
  TFile.WriteAllText(FRegistryPath, Json, TEncoding.UTF8);
end;

function TServerCompositionTests.StatusOf(const Method, Url: string): Integer;
begin
  const Client = THTTPClient.Create;
  try
    const Body = TStringStream.Create('token=unknown', TEncoding.UTF8);
    try
      Client.ContentType := 'application/x-www-form-urlencoded';
      const IsGet = (Method = 'GET');
      var Response: IHTTPResponse;
      if IsGet then
        Response := Client.Get(Url)
      else
        Response := Client.Post(Url, Body);
      Result := Response.StatusCode;
    finally
      Body.Free;
    end;
  finally
    Client.Free;
  end;
end;

procedure TServerCompositionTests.ResourceWithInactiveProviderFailsStartup;
begin
  WriteRegistry('microsoft');
  const Composition = TServerComposition.Create(LoadSettings);
  try
    var Message := '';
    try
      Composition.Start;
    except
      on E: EServerConfiguration do
        Message := E.Message;
    end;

    Assert.Contains(Message, 'microsoft');
    Assert.IsFalse(Composition.IsRunning);
  finally
    Composition.Free;
  end;
end;

procedure TServerCompositionTests.MissingLibraryTemplatesFailStartup;
begin
  WriteRegistry('microsoft');
  FVariables['MCPAUTH_MICROSOFT_CLIENT_ID']     := 'client-id';
  FVariables['MCPAUTH_MICROSOFT_CLIENT_SECRET'] := 'client-secret';
  FVariables['MCPAUTH_LIBRARY_TEMPLATES']       := TPath.Combine(TPath.GetTempPath, TGUID.NewGuid.ToString);
  var Composition := TServerComposition.Create(LoadSettings);
  try
    Assert.WillRaise(
      procedure
      begin
        Composition.Start;
      end,
      EServerConfiguration);
  finally
    Composition.Free;
  end;
end;

procedure TServerCompositionTests.StartedServerKeepsInternalEndpointsOffThePublicListener;
begin
  WriteRegistry('microsoft');
  FVariables['MCPAUTH_MICROSOFT_CLIENT_ID']     := 'client-id';
  FVariables['MCPAUTH_MICROSOFT_CLIENT_SECRET'] := 'client-secret';
  const Composition = TServerComposition.Create(LoadSettings);
  try
    Composition.Start;
    const PublicUrl = Format('http://%s:%d', [Loopback, Composition.PublicPort]);
    const InternalUrl = Format('http://%s:%d', [Loopback, Composition.InternalPort]);

    const MetadataStatus = StatusOf('GET', PublicUrl + '/.well-known/oauth-authorization-server');
    const PublicIntrospectStatus = StatusOf('POST', PublicUrl + '/internal/introspect');
    const InternalIntrospectStatus = StatusOf('POST', InternalUrl + '/internal/introspect');
    Composition.Stop;

    Assert.AreEqual(StatusOk, MetadataStatus);
    Assert.AreEqual(StatusNotFound, PublicIntrospectStatus);
    Assert.AreEqual(StatusUnauthorized, InternalIntrospectStatus);
    Assert.IsFalse(Composition.IsRunning);
  finally
    Composition.Free;
  end;
end;

end.
