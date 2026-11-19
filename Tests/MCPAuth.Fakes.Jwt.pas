unit MCPAuth.Fakes.Jwt;

interface

type
  TFakeJwt = class
  public
    class function Unsigned(const ClaimsJson: string): string; static;
    class function EncodePart(const Json: string): string; static;
    class function DecodePart(const Part: string): string; static;
  end;

implementation

uses
  System.SysUtils,
  System.NetEncoding;

const
  UnsignedHeader = '{"alg":"none","typ":"JWT"}';

{ TFakeJwt }

class function TFakeJwt.Unsigned(const ClaimsJson: string): string;
begin
  const Header = EncodePart(UnsignedHeader);
  const Payload = EncodePart(ClaimsJson);

  Result := Format('%s.%s.', [Header, Payload]);
end;

class function TFakeJwt.EncodePart(const Json: string): string;
begin
  const JsonBytes = TEncoding.UTF8.GetBytes(Json);

  Result := TNetEncoding.Base64URL.EncodeBytesToString(JsonBytes);
end;

class function TFakeJwt.DecodePart(const Part: string): string;
begin
  const PartBytes = TNetEncoding.Base64URL.DecodeStringToBytes(Part);

  Result := TEncoding.UTF8.GetString(PartBytes);
end;

end.
