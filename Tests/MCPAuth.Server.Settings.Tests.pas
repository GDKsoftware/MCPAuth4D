unit MCPAuth.Server.Settings.Tests;

interface

uses
  DUnitX.TestFramework,
  Spring.Collections,
  MCPAuth.Server.Settings;

type
  [TestFixture]
  TServerSettingsTests = class
  private
    FVariables: IDictionary<string, string>;

    function Load: TServerSettings;
    function MessageOfFailedLoad: string;

  public
    [Setup]
    procedure Setup;

    [Test]
    procedure ReadsSettingsFromEnvironment;

    [Test]
    procedure UsesDefaultsForOptionalVariables;

    [Test]
    procedure MissingIssuerRaisesWithNameOnly;

    [Test]
    [TestCase('Registry', 'MCPAUTH_REGISTRY')]
    [TestCase('MasterKey', 'MCPAUTH_MASTER_KEY')]
    procedure MissingRequiredVariableRaisesWithItsName(const Name: string);

    [Test]
    procedure PostgresStoreRequiresDatabase;

    [Test]
    procedure InvalidPortRaisesWithoutTheValue;

    [Test]
    procedure UnknownStoreRaisesWithoutTheValue;

    [Test]
    procedure CertificateWinsOverSecretWithWarning;

    [Test]
    procedure MicrosoftNeedsClientIdAndCredential;

    [Test]
    procedure IssuerLosesTrailingSlash;
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  System.NetEncoding,
  MCPAuth.Server.Exceptions;

const
  KeyLength = 32;
  ExecutableFolder = 'C:\does-not-exist\bin';

{ TServerSettingsTests }

procedure TServerSettingsTests.Setup;
begin
  var Key: TBytes;
  SetLength(Key, KeyLength);
  FillChar(Key[0], KeyLength, 7);

  FVariables := TCollections.CreateDictionary<string, string>;
  FVariables['MCPAUTH_ISSUER']       := 'https://auth.example.test';
  FVariables['MCPAUTH_REGISTRY']     := '/etc/mcpauth/registry.json';
  FVariables['MCPAUTH_MASTER_KEY']   := TNetEncoding.Base64.EncodeBytesToString(Key);
end;

function TServerSettingsTests.Load: TServerSettings;
begin
  Result := TServerSettings.FromVariables(
    function(const Name: string): string
    begin
      if not FVariables.TryGetValue(Name, Result) then
        Result := '';
    end,
    ExecutableFolder);
end;

function TServerSettingsTests.MessageOfFailedLoad: string;
begin
  Result := '';
  try
    Load;
  except
    on E: EServerConfiguration do
      Result := E.Message;
  end;
end;

procedure TServerSettingsTests.ReadsSettingsFromEnvironment;
begin
  FVariables['MCPAUTH_PUBLIC_PORT']             := '9100';
  FVariables['MCPAUTH_PUBLIC_BIND']             := '0.0.0.0';
  FVariables['MCPAUTH_INTERNAL_PORT']           := '9101';
  FVariables['MCPAUTH_INTERNAL_BIND']           := '10.0.0.5';
  FVariables['MCPAUTH_STORE']                   := 'postgres';
  FVariables['MCPAUTH_DB']                      := 'DriverID=PG;Server=db.example.test';
  FVariables['MCPAUTH_MIGRATIONS']              := '/opt/mcpauth/migrations';
  FVariables['MCPAUTH_TEMPLATES']               := '/opt/project/templates';
  FVariables['MCPAUTH_LIBRARY_TEMPLATES']       := '/opt/mcpauth/templates';
  FVariables['MCPAUTH_MICROSOFT_CLIENT_ID']     := 'client-id';
  FVariables['MCPAUTH_MICROSOFT_CLIENT_SECRET'] := 'client-secret';
  FVariables['MCPAUTH_ALLOW_HTTP_RESOURCES']    := '1';

  const Settings = Load;

  Assert.AreEqual('https://auth.example.test', Settings.Issuer);
  Assert.AreEqual(9100, Integer(Settings.PublicPort));
  Assert.AreEqual('0.0.0.0', Settings.PublicBind);
  Assert.AreEqual(9101, Integer(Settings.InternalPort));
  Assert.AreEqual('10.0.0.5', Settings.InternalBind);
  Assert.AreEqual('/etc/mcpauth/registry.json', Settings.RegistryPath);
  Assert.AreEqual<TServerStoreKind>(TServerStoreKind.Postgres, Settings.Store);
  Assert.AreEqual('DriverID=PG;Server=db.example.test', Settings.DatabaseConnection);
  Assert.AreEqual('/opt/mcpauth/migrations', Settings.MigrationsPath);
  Assert.AreEqual('/opt/project/templates', Settings.ProjectTemplatesPath);
  Assert.AreEqual('/opt/mcpauth/templates', Settings.LibraryTemplatesPath);
  Assert.AreEqual('client-id', Settings.MicrosoftClientId);
  Assert.AreEqual('client-secret', Settings.MicrosoftClientSecret);
  Assert.IsTrue(Settings.IsMicrosoftActive);
  Assert.IsFalse(Settings.UsesMicrosoftCertificate);
  Assert.IsTrue(Settings.AllowHttpResources);
  Assert.IsNotNull(Settings.KeyRing);
  Assert.AreEqual(0, Integer(Length(Settings.Warnings)));
end;

procedure TServerSettingsTests.UsesDefaultsForOptionalVariables;
begin
  const Settings = Load;

  Assert.AreEqual(8100, Integer(Settings.PublicPort));
  Assert.AreEqual('127.0.0.1', Settings.PublicBind);
  Assert.AreEqual(8101, Integer(Settings.InternalPort));
  Assert.AreEqual('127.0.0.1', Settings.InternalBind);
  Assert.AreEqual<TServerStoreKind>(TServerStoreKind.Memory, Settings.Store);
  Assert.AreEqual('', Settings.ProjectTemplatesPath);
  Assert.AreEqual(TPath.Combine(ExecutableFolder, 'templates'), Settings.LibraryTemplatesPath);
  Assert.AreEqual(TPath.Combine(ExecutableFolder, 'migrations'), Settings.MigrationsPath);
  Assert.IsFalse(Settings.IsMicrosoftActive);
  Assert.IsFalse(Settings.AllowHttpResources);
end;

procedure TServerSettingsTests.MissingIssuerRaisesWithNameOnly;
begin
  FVariables.Remove('MCPAUTH_ISSUER');

  const Message = MessageOfFailedLoad;

  Assert.AreEqual('Missing environment variable MCPAUTH_ISSUER', Message);
end;

procedure TServerSettingsTests.MissingRequiredVariableRaisesWithItsName(const Name: string);
begin
  FVariables.Remove(Name);

  const Message = MessageOfFailedLoad;

  Assert.AreEqual(Format('Missing environment variable %s', [Name]), Message);
end;

procedure TServerSettingsTests.PostgresStoreRequiresDatabase;
begin
  FVariables['MCPAUTH_STORE'] := 'postgres';

  const Message = MessageOfFailedLoad;

  Assert.AreEqual('Missing environment variable MCPAUTH_DB', Message);
end;

procedure TServerSettingsTests.InvalidPortRaisesWithoutTheValue;
begin
  FVariables['MCPAUTH_PUBLIC_PORT'] := 'port-secret-value';

  const Message = MessageOfFailedLoad;

  Assert.Contains(Message, 'MCPAUTH_PUBLIC_PORT');
  Assert.DoesNotContain(Message, 'port-secret-value');
end;

procedure TServerSettingsTests.UnknownStoreRaisesWithoutTheValue;
begin
  FVariables['MCPAUTH_STORE'] := 'store-secret-value';

  const Message = MessageOfFailedLoad;

  Assert.Contains(Message, 'MCPAUTH_STORE');
  Assert.DoesNotContain(Message, 'store-secret-value');
end;

procedure TServerSettingsTests.CertificateWinsOverSecretWithWarning;
begin
  FVariables['MCPAUTH_MICROSOFT_CLIENT_ID']     := 'client-id';
  FVariables['MCPAUTH_MICROSOFT_CERTIFICATE']   := '/etc/mcpauth/microsoft.pem';
  FVariables['MCPAUTH_MICROSOFT_CLIENT_SECRET'] := 'client-secret';

  const Settings = Load;

  Assert.IsTrue(Settings.IsMicrosoftActive);
  Assert.IsTrue(Settings.UsesMicrosoftCertificate);
  Assert.AreEqual('/etc/mcpauth/microsoft.pem', Settings.MicrosoftCertificatePath);
  Assert.AreEqual(1, Integer(Length(Settings.Warnings)));
  Assert.DoesNotContain(Settings.Warnings[0], 'client-secret');
end;

procedure TServerSettingsTests.MicrosoftNeedsClientIdAndCredential;
begin
  FVariables['MCPAUTH_MICROSOFT_CLIENT_ID'] := 'client-id';
  const WithoutCredential = Load;

  FVariables.Remove('MCPAUTH_MICROSOFT_CLIENT_ID');
  FVariables['MCPAUTH_MICROSOFT_CLIENT_SECRET'] := 'client-secret';
  const WithoutClientId = Load;

  Assert.IsFalse(WithoutCredential.IsMicrosoftActive);
  Assert.IsFalse(WithoutClientId.IsMicrosoftActive);
end;

procedure TServerSettingsTests.IssuerLosesTrailingSlash;
begin
  FVariables['MCPAUTH_ISSUER'] := 'https://auth.example.test/';

  const Settings = Load;

  Assert.AreEqual('https://auth.example.test', Settings.Issuer);
end;

end.
