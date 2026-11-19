unit MCPAuth.Upstream.Credential.Secret.Tests;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  TClientSecretCredentialTests = class
  public
    [Test]
    procedure SecretCredentialAddsClientSecret;
  end;

implementation

uses
  Spring.Collections,
  MCPAuth.Fakes.UpstreamHttp,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.Upstream.Credential.Secret;

{ TClientSecretCredentialTests }

procedure TClientSecretCredentialTests.SecretCredentialAddsClientSecret;
begin
  const Credential: IClientCredential = TClientSecretCredential.Create('client-1', 'secret-value-1');
  const Fields: TArray<TPair<string, string>> = [TPair<string, string>.Create('grant_type', 'refresh_token')];

  var Request: TRecordedUpstreamRequest;
  Request.Fields := Credential.WithCredential('https://login.example.com/token', Fields);

  Assert.AreEqual<Integer>(3, Length(Request.Fields));
  Assert.AreEqual('refresh_token', Request.GetField('grant_type'));
  Assert.AreEqual('client-1', Request.GetField('client_id'));
  Assert.AreEqual('secret-value-1', Request.GetField('client_secret'));
end;

end.
