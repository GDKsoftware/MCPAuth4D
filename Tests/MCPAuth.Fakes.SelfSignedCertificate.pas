unit MCPAuth.Fakes.SelfSignedCertificate;

interface

uses
  System.SysUtils,
  TaurusTLSHeaders_types;

type
  // Generates a throwaway RSA key and self-signed certificate at test time,
  // so the repository holds no key material.
  TSelfSignedCertificate = class
  private
    FPrivateKey: PEVP_PKEY;
    FCertificate: PX509;

    procedure GenerateKey;
    procedure GenerateCertificate;
    procedure SetValidity;
    procedure SetSubject;
    function PemBytes: TBytes;
    function DerBytes: TBytes;
    procedure Check(const Succeeded: Boolean; const Step: string);

  public
    constructor Create;
    destructor Destroy; override;

    procedure SaveAsPem(const Path: string);
    function Thumbprint: string;
    function IsValidSignature(const SignedData, Signature: TBytes): Boolean;
  end;

implementation

uses
  System.IOUtils,
  System.Hash,
  System.NetEncoding,
  TaurusTLSHeaders_asn1,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_pem,
  TaurusTLSHeaders_x509,
  MCPAuth.Secret.OpenSsl;

const
  CertificateLifetimeSeconds = 3600;
  CertificateVersion3 = 2;
  CommonName: AnsiString = 'test-only';

resourcestring
  StepFailed = 'Generating the test certificate failed at %s';

{ TSelfSignedCertificate }

constructor TSelfSignedCertificate.Create;
begin
  inherited Create;
  TOpenSsl.EnsureLoaded;
  GenerateKey;
  GenerateCertificate;
end;

destructor TSelfSignedCertificate.Destroy;
begin
  if Assigned(FCertificate) then
    X509_free(FCertificate);
  if Assigned(FPrivateKey) then
    EVP_PKEY_free(FPrivateKey);
  inherited;
end;

procedure TSelfSignedCertificate.GenerateKey;
begin
  const Context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil);
  Check(Assigned(Context), 'EVP_PKEY_CTX_new_id');
  try
    Check(EVP_PKEY_keygen_init(Context) = 1, 'EVP_PKEY_keygen_init');
    Check(EVP_PKEY_keygen(Context, @FPrivateKey) = 1, 'EVP_PKEY_keygen');
  finally
    EVP_PKEY_CTX_free(Context);
  end;
end;

procedure TSelfSignedCertificate.GenerateCertificate;
begin
  FCertificate := X509_new;
  Check(Assigned(FCertificate), 'X509_new');

  Check(X509_set_version(FCertificate, CertificateVersion3) = 1, 'X509_set_version');
  const SerialNumber = X509_get_serialNumber(FCertificate);
  Check(ASN1_INTEGER_set(SerialNumber, 1) = 1, 'ASN1_INTEGER_set');
  SetValidity;
  Check(X509_set_pubkey(FCertificate, FPrivateKey) = 1, 'X509_set_pubkey');
  SetSubject;
  Check(X509_sign(FCertificate, FPrivateKey, EVP_sha256) > 0, 'X509_sign');
end;

procedure TSelfSignedCertificate.SetValidity;
begin
  const NotBefore = X509_getm_notBefore(FCertificate);
  const NotAfter = X509_getm_notAfter(FCertificate);

  Check(Assigned(X509_gmtime_adj(NotBefore, 0)), 'X509_gmtime_adj notBefore');
  Check(Assigned(X509_gmtime_adj(NotAfter, CertificateLifetimeSeconds)), 'X509_gmtime_adj notAfter');
end;

procedure TSelfSignedCertificate.SetSubject;
begin
  const Name = X509_get_subject_name(FCertificate);
  const NameBytes = PByte(PAnsiChar(CommonName));

  Check(X509_NAME_add_entry_by_txt(Name, 'CN', MBSTRING_ASC, NameBytes, -1, -1, 0) = 1, 'X509_NAME_add_entry_by_txt');
  Check(X509_set_issuer_name(FCertificate, Name) = 1, 'X509_set_issuer_name');
end;

procedure TSelfSignedCertificate.SaveAsPem(const Path: string);
begin
  TFile.WriteAllBytes(Path, PemBytes);
end;

function TSelfSignedCertificate.PemBytes: TBytes;
begin
  const Bio = BIO_new(BIO_s_mem);
  Check(Assigned(Bio), 'BIO_new');
  try
    Check(PEM_write_bio_X509(Bio, FCertificate) = 1, 'PEM_write_bio_X509');
    Check(PEM_write_bio_PrivateKey(Bio, FPrivateKey, nil, nil, 0, nil, nil) = 1, 'PEM_write_bio_PrivateKey');

    var Data: Pointer := nil;
    const PemLength = BIO_get_mem_data(Bio, Data);
    SetLength(Result, PemLength);
    Move(Data^, Result[0], PemLength);
  finally
    BIO_free(Bio);
  end;
end;

function TSelfSignedCertificate.Thumbprint: string;
begin
  var Hash := THashSHA2.Create(THashSHA2.TSHA2Version.SHA256);
  Hash.Update(DerBytes);

  const Digest = Hash.HashAsBytes;
  Result := TNetEncoding.Base64URL.EncodeBytesToString(Digest);
end;

function TSelfSignedCertificate.DerBytes: TBytes;
begin
  const DerLength = i2d_X509(FCertificate, nil);
  Check(DerLength > 0, 'i2d_X509');

  SetLength(Result, DerLength);
  var Cursor := PByte(Result);
  i2d_X509(FCertificate, @Cursor);
end;

function TSelfSignedCertificate.IsValidSignature(const SignedData, Signature: TBytes): Boolean;
begin
  const Context = EVP_MD_CTX_new;
  Check(Assigned(Context), 'EVP_MD_CTX_new');
  try
    Check(EVP_DigestVerifyInit(Context, nil, EVP_sha256, nil, FPrivateKey) = 1, 'EVP_DigestVerifyInit');

    const Verified = EVP_DigestVerify(Context, PByte(Signature), Length(Signature), PByte(SignedData), Length(SignedData));
    Result := (Verified = 1);
  finally
    EVP_MD_CTX_free(Context);
  end;
end;

procedure TSelfSignedCertificate.Check(const Succeeded: Boolean; const Step: string);
begin
  if not Succeeded then
    raise EInvalidOpException.CreateFmt(StepFailed, [Step]);
end;

end.
