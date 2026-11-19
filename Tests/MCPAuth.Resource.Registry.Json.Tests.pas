unit MCPAuth.Resource.Registry.Json.Tests;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  TJsonResourceRegistryTests = class
  public
    [Test]
    procedure LoadsResourcesWithProviders;

    [Test]
    procedure TryGetByUriIsExactMatch;

    [Test]
    procedure ScopesForProviderIsSortedUnion;

    [Test]
    procedure ScopesForUnknownProviderIsEmpty;

    [Test]
    procedure DuplicateServiceIdIsInvalid;

    [Test]
    procedure DuplicateResourceIsInvalid;

    [Test]
    procedure HttpResourceIsInvalid;

    [Test]
    procedure HttpResourceIsAllowedWhenRequested;

    [Test]
    [TestCase('NotJson', 'this is not json')]
    [TestCase('NoResourcesArray', '{}')]
    [TestCase('ResourceNotObject', '{"resources":[1]}')]
    [TestCase('MissingServiceId', '{"resources":[{"resource":"https://a.example/mcp","name":"A","service_secret_sha256":"x","providers":[]}]}')]
    [TestCase('MissingSecretHash', '{"resources":[{"resource":"https://a.example/mcp","name":"A","service_id":"a","providers":[]}]}')]
    [TestCase('ProvidersNotArray', '{"resources":[{"resource":"https://a.example/mcp","name":"A","service_id":"a","service_secret_sha256":"x","providers":"microsoft"}]}')]
    [TestCase('ScopeNotString', '{"resources":[{"resource":"https://a.example/mcp","name":"A","service_id":"a","service_secret_sha256":"x","providers":[{"provider":"microsoft","scopes":[1]}]}]}')]
    procedure MalformedDocumentIsInvalid(const Json: string);

    [Test]
    procedure InvalidMessageNamesFieldButNotSecret;

    [Test]
    procedure FromFileLoadsResources;

    [Test]
    procedure FromFileMissingFileIsInvalid;
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  MCPAuth.Resource.Types,
  MCPAuth.Resource.Interfaces,
  MCPAuth.Resource.Exceptions,
  MCPAuth.Resource.Registry.Json;

const
  MailUri = 'https://m365.example.com/mcp';
  NotesUri = 'https://notes.example.com/mcp';
  SecretHash = 'c2VjcmV0LWhhc2gtdmFsdWU';
  MailProviders = '[{"provider":"microsoft","scopes":["Mail.ReadWrite","User.Read"]}]';
  NotesProviders = '[{"provider":"microsoft","scopes":["User.Read","Files.Read","Mail.ReadWrite"]}]';

function ResourceJson(const Uri, ServiceId, ProvidersJson: string): string;
begin
  Result := Format('{"resource":"%s","name":"Name of %s","service_id":"%s","service_secret_sha256":"%s","providers":%s}',
                   [Uri, ServiceId, ServiceId, SecretHash, ProvidersJson]);
end;

function RegistryJson(const Resources: TArray<string>): string;
begin
  Result := Format('{"resources":[%s]}', [string.Join(',', Resources)]);
end;

{ TJsonResourceRegistryTests }

procedure TJsonResourceRegistryTests.LoadsResourcesWithProviders;
begin
  const Json = RegistryJson([ResourceJson(MailUri, 'mailmcp', MailProviders)]);

  const Registry = TJsonResourceRegistry.FromJson(Json);

  var Resource: TResourceDefinition;
  Assert.IsTrue(Registry.TryGetByServiceId('mailmcp', Resource));
  Assert.AreEqual(MailUri, Resource.ResourceUri);
  Assert.AreEqual('Name of mailmcp', Resource.DisplayName);
  Assert.AreEqual(SecretHash, Resource.ServiceSecretHash);
  Assert.AreEqual(1, Integer(Length(Resource.Providers)));
  Assert.AreEqual('microsoft', Resource.Providers[0].Provider);
  Assert.AreEqual(2, Integer(Length(Resource.Providers[0].Scopes)));
  Assert.AreEqual('Mail.ReadWrite', Resource.Providers[0].Scopes[0]);
  Assert.AreEqual(1, Integer(Length(Registry.All)));
end;

procedure TJsonResourceRegistryTests.TryGetByUriIsExactMatch;
begin
  const Json = RegistryJson([ResourceJson(MailUri, 'mailmcp', MailProviders)]);
  const Registry = TJsonResourceRegistry.FromJson(Json);

  var Resource: TResourceDefinition;
  Assert.IsTrue(Registry.TryGetByUri(MailUri, Resource));
  Assert.AreEqual('mailmcp', Resource.ServiceId);
  Assert.IsFalse(Registry.TryGetByUri(MailUri + '/', Resource));
  Assert.IsFalse(Registry.TryGetByUri('https://other.example.com/mcp', Resource));
end;

procedure TJsonResourceRegistryTests.ScopesForProviderIsSortedUnion;
begin
  const Json = RegistryJson([ResourceJson(MailUri, 'mailmcp', MailProviders),
                             ResourceJson(NotesUri, 'notesmcp', NotesProviders)]);
  const Registry = TJsonResourceRegistry.FromJson(Json);

  const Scopes = Registry.ScopesForProvider('microsoft');

  Assert.AreEqual(3, Integer(Length(Scopes)));
  Assert.AreEqual('Files.Read', Scopes[0]);
  Assert.AreEqual('Mail.ReadWrite', Scopes[1]);
  Assert.AreEqual('User.Read', Scopes[2]);
end;

procedure TJsonResourceRegistryTests.ScopesForUnknownProviderIsEmpty;
begin
  const Json = RegistryJson([ResourceJson(MailUri, 'mailmcp', MailProviders)]);
  const Registry = TJsonResourceRegistry.FromJson(Json);

  const Scopes = Registry.ScopesForProvider('google');

  Assert.AreEqual(0, Integer(Length(Scopes)));
end;

procedure TJsonResourceRegistryTests.DuplicateServiceIdIsInvalid;
begin
  const Json = RegistryJson([ResourceJson(MailUri, 'same', MailProviders),
                             ResourceJson(NotesUri, 'same', NotesProviders)]);

  Assert.WillRaise(
    procedure
    begin
      TJsonResourceRegistry.FromJson(Json);
    end,
    EResourceRegistryInvalid);
end;

procedure TJsonResourceRegistryTests.DuplicateResourceIsInvalid;
begin
  const Json = RegistryJson([ResourceJson(MailUri, 'one', MailProviders),
                             ResourceJson(MailUri, 'two', NotesProviders)]);

  Assert.WillRaise(
    procedure
    begin
      TJsonResourceRegistry.FromJson(Json);
    end,
    EResourceRegistryInvalid);
end;

procedure TJsonResourceRegistryTests.HttpResourceIsInvalid;
begin
  const Json = RegistryJson([ResourceJson('http://m365.example.com/mcp', 'mailmcp', MailProviders)]);

  Assert.WillRaise(
    procedure
    begin
      TJsonResourceRegistry.FromJson(Json);
    end,
    EResourceRegistryInvalid);
end;

procedure TJsonResourceRegistryTests.HttpResourceIsAllowedWhenRequested;
begin
  const Json = RegistryJson([ResourceJson('http://localhost:8080/mcp', 'mailmcp', MailProviders)]);

  const Registry = TJsonResourceRegistry.FromJson(Json, True);

  var Resource: TResourceDefinition;
  Assert.IsTrue(Registry.TryGetByUri('http://localhost:8080/mcp', Resource));
end;

procedure TJsonResourceRegistryTests.MalformedDocumentIsInvalid(const Json: string);
begin
  Assert.WillRaise(
    procedure
    begin
      TJsonResourceRegistry.FromJson(Json);
    end,
    EResourceRegistryInvalid);
end;

procedure TJsonResourceRegistryTests.InvalidMessageNamesFieldButNotSecret;
begin
  const Json = Format('{"resources":[{"resource":"https://a.example/mcp","name":"A","service_secret_sha256":"%s","providers":[]}]}',
                      [SecretHash]);

  var Message := '';
  try
    TJsonResourceRegistry.FromJson(Json);
  except
    on E: EResourceRegistryInvalid do
      Message := E.Message;
  end;

  Assert.IsTrue(Message.Contains('service_id'), 'The message names the field');
  Assert.IsTrue(Message.Contains('resources[0]'), 'The message names the entry');
  Assert.IsFalse(Message.Contains(SecretHash), 'The message never contains the secret hash');
end;

procedure TJsonResourceRegistryTests.FromFileLoadsResources;
begin
  const Path = TPath.Combine(TPath.GetTempPath, TGUID.NewGuid.ToString + '.json');
  TFile.WriteAllText(Path, RegistryJson([ResourceJson(MailUri, 'mailmcp', MailProviders)]));
  try
    const Registry = TJsonResourceRegistry.FromFile(Path);

    var Resource: TResourceDefinition;
    Assert.IsTrue(Registry.TryGetByUri(MailUri, Resource));
  finally
    TFile.Delete(Path);
  end;
end;

procedure TJsonResourceRegistryTests.FromFileMissingFileIsInvalid;
begin
  const Path = TPath.Combine(TPath.GetTempPath, TGUID.NewGuid.ToString + '.json');

  Assert.WillRaise(
    procedure
    begin
      TJsonResourceRegistry.FromFile(Path);
    end,
    EResourceRegistryInvalid);
end;

end.
