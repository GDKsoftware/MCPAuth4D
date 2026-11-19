unit MCPAuth.Secret.Token;

interface

uses
  MCPAuth.Secret.Interfaces;

type
  TTokenGenerator = class(TInterfacedObject, ITokenGenerator)
  public
    function NewToken: string;
  end;

implementation

uses
  System.NetEncoding,
  MCPAuth.Secret.OpenSsl;

const
  TokenByteLength = 32;

{ TTokenGenerator }

function TTokenGenerator.NewToken: string;
begin
  const Bytes = TOpenSsl.RandomBytes(TokenByteLength);

  Result := TNetEncoding.Base64URL.EncodeBytesToString(Bytes);
end;

end.
