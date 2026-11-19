unit MCPAuth.Upstream.Credential.Certificate.Tests;

interface

uses
  System.JSON,
  DUnitX.TestFramework,
  MCPAuth.Fakes.Clock,
  MCPAuth.Fakes.UpstreamHttp,
  MCPAuth.Fakes.SelfSignedCertificate,
  MCPAuth.Clock.Interfaces;

type
  [TestFixture]
  TCertificateCredentialTests = class
  private
    FCertificate: TSelfSignedCertificate;
    FPemPath: string;
    FClock: TFakeClock;
    FClockReference: IClock;

    function RequestWithAssertion: TRecordedUpstreamRequest;
    function DecodeJsonPart(const Part: string): TJSONObject;
    function RaisedMessageOfLoad(const PemPath: string): string;

  public
    [SetupFixture]
    procedure SetupFixture;

    [TearDownFixture]
    procedure TearDownFixture;

    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure CertificateCredentialAddsSignedAssertion;

    [Test]
    procedure AssertionJtiIsUniquePerRequest;

    [Test]
    procedure MissingPemFileRaisesWithoutContent;

    [Test]
    procedure InvalidPemFileRaisesWithoutContent;

    [Test]
    procedure PemWithoutPrivateKeyRaises;
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  System.DateUtils,
  System.NetEncoding,
  Spring.Collections,
  MCPAuth.Fakes.Jwt,
  MCPAuth.Secret.Interfaces,
  MCPAuth.Secret.Token,
  MCPAuth.Upstream.Exceptions,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.Upstream.Credential.Certificate;

const
  ClientId = 'client-1';
  TokenUrl = 'https://login.example.com/tenant/oauth2/v2.0/token';
  JwtBearerAssertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
  SecretLookingContent = 'not-a-pem-but-secret-looking-content';

{ TCertificateCredentialTests }

procedure TCertificateCredentialTests.SetupFixture;
begin
  FCertificate := TSelfSignedCertificate.Create;
  FPemPath     := TPath.Combine(TPath.GetTempPath, Format('mcpauth-test-only-%s.pem', [TGUID.NewGuid.ToString]));
  FCertificate.SaveAsPem(FPemPath);
end;

procedure TCertificateCredentialTests.TearDownFixture;
begin
  TFile.Delete(FPemPath);
  FCertificate.Free;
end;

procedure TCertificateCredentialTests.Setup;
begin
  FClock          := TFakeClock.Create(EncodeDateTime(2026, 11, 19, 10, 0, 0, 0));
  FClockReference := FClock;
end;

procedure TCertificateCredentialTests.TearDown;
begin
  FClock          := nil;
  FClockReference := nil;
end;

function TCertificateCredentialTests.RequestWithAssertion: TRecordedUpstreamRequest;
begin
  const TokenGenerator: ITokenGenerator = TTokenGenerator.Create;
  const Credential = TCertificateCredential.FromPemFile(ClientId, FPemPath, FClockReference, TokenGenerator);
  const Fields: TArray<TPair<string, string>> = [TPair<string, string>.Create('grant_type', 'refresh_token')];

  Result.Url    := TokenUrl;
  Result.Fields := Credential.WithCredential(TokenUrl, Fields);
end;

function TCertificateCredentialTests.DecodeJsonPart(const Part: string): TJSONObject;
begin
  const Json = TFakeJwt.DecodePart(Part);

  Result := TJSONObject.ParseJSONValue(Json) as TJSONObject;
end;

function TCertificateCredentialTests.RaisedMessageOfLoad(const PemPath: string): string;
begin
  Result := '';
  try
    TCertificateCredential.FromPemFile(ClientId, PemPath);
  except
    on E: EUpstreamCredentialInvalid do
      Result := E.Message;
  end;
end;

procedure TCertificateCredentialTests.CertificateCredentialAddsSignedAssertion;
begin
  const Request = RequestWithAssertion;

  Assert.AreEqual('refresh_token', Request.GetField('grant_type'));
  Assert.AreEqual(ClientId, Request.GetField('client_id'));
  Assert.AreEqual(JwtBearerAssertionType, Request.GetField('client_assertion_type'));
  Assert.IsFalse(Request.HasField('client_secret'));

  const Parts = Request.GetField('client_assertion').Split(['.']);
  Assert.AreEqual<Integer>(3, Length(Parts));

  const Header = DecodeJsonPart(Parts[0]);
  try
    Assert.AreEqual('RS256', Header.GetValue<string>('alg'));
    Assert.AreEqual('JWT', Header.GetValue<string>('typ'));
    Assert.AreEqual(FCertificate.Thumbprint, Header.GetValue<string>('x5t#S256'));
  finally
    Header.Free;
  end;

  const Claims = DecodeJsonPart(Parts[1]);
  try
    const IssuedAt = Claims.GetValue<Int64>('iat');
    Assert.AreEqual(TokenUrl, Claims.GetValue<string>('aud'));
    Assert.AreEqual(ClientId, Claims.GetValue<string>('iss'));
    Assert.AreEqual(ClientId, Claims.GetValue<string>('sub'));
    Assert.IsNotEmpty(Claims.GetValue<string>('jti'));
    Assert.AreEqual(DateTimeToUnix(FClock.NowUtc, True), IssuedAt);
    Assert.AreEqual(IssuedAt, Claims.GetValue<Int64>('nbf'));
    Assert.AreEqual<Int64>(300, Claims.GetValue<Int64>('exp') - IssuedAt);
  finally
    Claims.Free;
  end;

  const SigningInput = Format('%s.%s', [Parts[0], Parts[1]]);
  const SignedData = TEncoding.ASCII.GetBytes(SigningInput);
  const Signature = TNetEncoding.Base64URL.DecodeStringToBytes(Parts[2]);
  Assert.IsTrue(FCertificate.IsValidSignature(SignedData, Signature), 'The assertion signature must verify with the certificate key');
end;

procedure TCertificateCredentialTests.AssertionJtiIsUniquePerRequest;
begin
  const First = RequestWithAssertion.GetField('client_assertion').Split(['.']);
  const Second = RequestWithAssertion.GetField('client_assertion').Split(['.']);

  const FirstClaims = DecodeJsonPart(First[1]);
  const SecondClaims = DecodeJsonPart(Second[1]);
  try
    Assert.AreNotEqual(FirstClaims.GetValue<string>('jti'), SecondClaims.GetValue<string>('jti'));
  finally
    SecondClaims.Free;
    FirstClaims.Free;
  end;
end;

procedure TCertificateCredentialTests.MissingPemFileRaisesWithoutContent;
begin
  const MissingPath = TPath.Combine(TPath.GetTempPath, Format('mcpauth-missing-%s.pem', [TGUID.NewGuid.ToString]));

  const RaisedMessage = RaisedMessageOfLoad(MissingPath);

  Assert.IsNotEmpty(RaisedMessage, 'FromPemFile must raise EUpstreamCredentialInvalid');
  Assert.Contains(RaisedMessage, MissingPath);
end;

procedure TCertificateCredentialTests.InvalidPemFileRaisesWithoutContent;
begin
  const InvalidPath = TPath.Combine(TPath.GetTempPath, Format('mcpauth-invalid-%s.pem', [TGUID.NewGuid.ToString]));
  TFile.WriteAllText(InvalidPath, SecretLookingContent);
  try
    const RaisedMessage = RaisedMessageOfLoad(InvalidPath);

    Assert.IsNotEmpty(RaisedMessage, 'FromPemFile must raise EUpstreamCredentialInvalid');
    Assert.Contains(RaisedMessage, InvalidPath);
    Assert.DoesNotContain(RaisedMessage, SecretLookingContent);
  finally
    TFile.Delete(InvalidPath);
  end;
end;

procedure TCertificateCredentialTests.PemWithoutPrivateKeyRaises;
begin
  const PemText = TFile.ReadAllText(FPemPath);
  const KeyStart = PemText.IndexOf('-----BEGIN PRIVATE KEY-----');
  const CertificateOnly = PemText.Substring(0, KeyStart);

  const CertificatePath = TPath.Combine(TPath.GetTempPath, Format('mcpauth-certonly-%s.pem', [TGUID.NewGuid.ToString]));
  TFile.WriteAllText(CertificatePath, CertificateOnly);
  try
    const RaisedMessage = RaisedMessageOfLoad(CertificatePath);

    Assert.IsNotEmpty(RaisedMessage, 'FromPemFile must raise EUpstreamCredentialInvalid');
    Assert.Contains(RaisedMessage, CertificatePath);
  finally
    TFile.Delete(CertificatePath);
  end;
end;

end.
