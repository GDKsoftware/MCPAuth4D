unit MCPAuth.Resource.ServiceAuth.Tests;

interface

uses
  DUnitX.TestFramework,
  MCPAuth.Resource.Interfaces,
  MCPAuth.Resource.ServiceAuth;

type
  [TestFixture]
  TServiceAuthenticatorTests = class
  private
    FRegistry: IResourceRegistry;
    FAuthenticator: TServiceAuthenticator;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure ValidBasicCredentialsAuthenticate;

    [Test]
    procedure SchemeIsCaseInsensitive;

    [Test]
    procedure WrongSecretFails;

    [Test]
    procedure UnknownServiceFails;

    [Test]
    [TestCase('Empty', '')]
    [TestCase('Bearer', 'Bearer abc')]
    [TestCase('BasicWithoutValue', 'Basic')]
    [TestCase('BadBase64', 'Basic !!!???')]
    [TestCase('NoColon', 'Basic bWFpbG1jcA==')]
    [TestCase('EmptyId', 'Basic OnNlY3JldA==')]
    [TestCase('EmptySecret', 'Basic bWFpbG1jcDo=')]
    procedure MalformedHeaderFails(const Header: string);

    [Test]
    procedure HashSecretIsBase64UrlSha256;

    [Test]
    procedure FailureClearsResource;
  end;

implementation

uses
  System.SysUtils,
  System.NetEncoding,
  MCPAuth.Resource.Types,
  MCPAuth.Resource.Registry.Json;

const
  ServiceId = 'mailmcp';
  ServiceSecret = 'correct horse: battery staple';
  HashOfAbc = 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0';

function BasicHeader(const Id, Secret: string): string;
begin
  const Credentials = TEncoding.UTF8.GetBytes(Format('%s:%s', [Id, Secret]));
  Result := 'Basic ' + TNetEncoding.Base64.EncodeBytesToString(Credentials);
end;

{ TServiceAuthenticatorTests }

procedure TServiceAuthenticatorTests.Setup;
begin
  const Hash = TServiceAuthenticator.HashSecret(ServiceSecret);
  const Json = Format('{"resources":[{"resource":"https://m365.example.com/mcp","name":"Mail","service_id":"%s",' +
                      '"service_secret_sha256":"%s","providers":[]}]}', [ServiceId, Hash]);
  FRegistry := TJsonResourceRegistry.FromJson(Json);
  FAuthenticator := TServiceAuthenticator.Create(FRegistry);
end;

procedure TServiceAuthenticatorTests.TearDown;
begin
  FAuthenticator.Free;
  FRegistry := nil;
end;

procedure TServiceAuthenticatorTests.ValidBasicCredentialsAuthenticate;
begin
  var Resource: TResourceDefinition;

  const Actual = FAuthenticator.TryAuthenticate(BasicHeader(ServiceId, ServiceSecret), Resource);

  Assert.IsTrue(Actual);
  Assert.AreEqual('https://m365.example.com/mcp', Resource.ResourceUri);
  Assert.AreEqual(ServiceId, Resource.ServiceId);
end;

procedure TServiceAuthenticatorTests.SchemeIsCaseInsensitive;
begin
  var Resource: TResourceDefinition;
  const Header = 'basic ' + BasicHeader(ServiceId, ServiceSecret).Substring(6);

  const Actual = FAuthenticator.TryAuthenticate(Header, Resource);

  Assert.IsTrue(Actual);
end;

procedure TServiceAuthenticatorTests.WrongSecretFails;
begin
  var Resource: TResourceDefinition;

  const Actual = FAuthenticator.TryAuthenticate(BasicHeader(ServiceId, 'wrong'), Resource);

  Assert.IsFalse(Actual);
end;

procedure TServiceAuthenticatorTests.UnknownServiceFails;
begin
  var Resource: TResourceDefinition;

  const Actual = FAuthenticator.TryAuthenticate(BasicHeader('other', ServiceSecret), Resource);

  Assert.IsFalse(Actual);
end;

procedure TServiceAuthenticatorTests.MalformedHeaderFails(const Header: string);
begin
  var Resource: TResourceDefinition;

  const Actual = FAuthenticator.TryAuthenticate(Header, Resource);

  Assert.IsFalse(Actual);
end;

procedure TServiceAuthenticatorTests.HashSecretIsBase64UrlSha256;
begin
  const Actual = TServiceAuthenticator.HashSecret('abc');

  Assert.AreEqual(HashOfAbc, Actual);
end;

procedure TServiceAuthenticatorTests.FailureClearsResource;
begin
  var Resource: TResourceDefinition;
  Resource.ServiceId := 'leftover';

  FAuthenticator.TryAuthenticate(BasicHeader(ServiceId, 'wrong'), Resource);

  Assert.AreEqual('', Resource.ServiceId);
end;

end.
