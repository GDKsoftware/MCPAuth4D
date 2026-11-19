unit MCPAuth.OAuth.Metadata.Tests;

interface

uses
  System.JSON,
  DUnitX.TestFramework,
  MCPAuth.OAuth.Settings,
  MCPAuth.OAuth.Metadata;

type
  [TestFixture]
  TAuthorizationServerMetadataTests = class
  private
    FSettings: TMCPAuthSettings;
    FMetadata: TJSONObject;

    function ArrayAsText(const Name: string): string;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure MetadataHasAllEndpointsUnderIssuer;

    [Test]
    procedure MetadataAdvertisesOnlyS256AndPublicClients;

    [Test]
    procedure MetadataAdvertisesCodeFlowAndScope;

    [Test]
    procedure TrailingSlashOnIssuerDoesNotDoubleUp;
  end;

implementation

uses
  System.SysUtils;

const
  Issuer = 'https://auth.example.com';

{ TAuthorizationServerMetadataTests }

procedure TAuthorizationServerMetadataTests.Setup;
begin
  FSettings := TMCPAuthSettings.Defaults(Issuer);
  FMetadata := TAuthorizationServerMetadata.Build(FSettings);
end;

procedure TAuthorizationServerMetadataTests.TearDown;
begin
  FMetadata.Free;
end;

function TAuthorizationServerMetadataTests.ArrayAsText(const Name: string): string;
begin
  const Values = FMetadata.GetValue<TJSONArray>(Name);
  var Items := TArray<string>.Create();
  for var Value in Values do
    Items := Items + [Value.Value];

  Result := string.Join(',', Items);
end;

procedure TAuthorizationServerMetadataTests.MetadataHasAllEndpointsUnderIssuer;
begin
  Assert.AreEqual(Issuer, FMetadata.GetValue<string>('issuer'));
  Assert.AreEqual(Issuer + '/authorize', FMetadata.GetValue<string>('authorization_endpoint'));
  Assert.AreEqual(Issuer + '/token', FMetadata.GetValue<string>('token_endpoint'));
  Assert.AreEqual(Issuer + '/register', FMetadata.GetValue<string>('registration_endpoint'));
  Assert.AreEqual(Issuer + '/revoke', FMetadata.GetValue<string>('revocation_endpoint'));
end;

procedure TAuthorizationServerMetadataTests.MetadataAdvertisesOnlyS256AndPublicClients;
begin
  Assert.AreEqual('S256', ArrayAsText('code_challenge_methods_supported'));
  Assert.AreEqual('none', ArrayAsText('token_endpoint_auth_methods_supported'));
end;

procedure TAuthorizationServerMetadataTests.MetadataAdvertisesCodeFlowAndScope;
begin
  Assert.AreEqual('code', ArrayAsText('response_types_supported'));
  Assert.AreEqual('authorization_code,refresh_token', ArrayAsText('grant_types_supported'));
  Assert.AreEqual(FSettings.Scope, ArrayAsText('scopes_supported'));
end;

procedure TAuthorizationServerMetadataTests.TrailingSlashOnIssuerDoesNotDoubleUp;
begin
  FMetadata.Free;
  FMetadata := TAuthorizationServerMetadata.Build(TMCPAuthSettings.Defaults(Issuer + '/'));

  Assert.AreEqual(Issuer + '/token', FMetadata.GetValue<string>('token_endpoint'));
end;

end.
