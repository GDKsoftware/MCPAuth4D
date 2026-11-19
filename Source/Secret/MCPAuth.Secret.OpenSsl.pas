unit MCPAuth.Secret.OpenSsl;

interface

uses
  System.SysUtils;

type
  TOpenSsl = class
  public
    class procedure EnsureLoaded; static;
    class function RandomBytes(const Count: Integer): TBytes; static;
  end;

implementation

uses
  TaurusTLSLoader,
  TaurusTLSHeaders_rand,
  MCPAuth.Secret.Interfaces;

resourcestring
  OpenSslNotLoaded = 'The OpenSSL 3 libraries (libcrypto, libssl) could not be loaded';
  RandomBytesFailed = 'OpenSSL could not generate random bytes';

{ TOpenSsl }

class procedure TOpenSsl.EnsureLoaded;
begin
  const Loader = GetOpenSSLLoader;
  const IsLoaded = (Assigned(Loader) and Loader.Load);
  if not IsLoaded then
    raise ESecretError.Create(OpenSslNotLoaded);
end;

class function TOpenSsl.RandomBytes(const Count: Integer): TBytes;
begin
  EnsureLoaded;

  SetLength(Result, Count);
  const Succeeded = (RAND_bytes(PByte(Result), Count) = 1);
  if not Succeeded then
    raise ESecretError.Create(RandomBytesFailed);
end;

end.
