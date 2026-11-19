unit MCPAuth.Secret.Hash;

interface

type
  TTokenHash = record
  public
    class function &Of(const Value: string): string; static;
    class function SameHash(const A, B: string): Boolean; static;
  end;

implementation

uses
  System.SysUtils,
  System.Hash,
  System.NetEncoding;

{ TTokenHash }

class function TTokenHash.&Of(const Value: string): string;
begin
  const ValueBytes = TEncoding.UTF8.GetBytes(Value);
  var Hash := THashSHA2.Create(THashSHA2.TSHA2Version.SHA256);
  Hash.Update(ValueBytes);

  const Digest = Hash.HashAsBytes;
  Result := TNetEncoding.Base64URL.EncodeBytesToString(Digest);
end;

class function TTokenHash.SameHash(const A, B: string): Boolean;
begin
  // The length of a hash is public; only the characters are compared in constant time.
  const HaveSameLength = (A.Length = B.Length);
  if not HaveSameLength then
    Exit(False);

  var Difference := 0;
  for var Index := 1 to A.Length do
  begin
    Difference := Difference or (Ord(A[Index]) xor Ord(B[Index]));
  end;

  Result := (Difference = 0);
end;

end.
