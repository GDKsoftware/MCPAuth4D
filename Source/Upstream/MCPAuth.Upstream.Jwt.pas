unit MCPAuth.Upstream.Jwt;

interface

uses
  System.SysUtils,
  System.JSON;

type
  // Decodes only the payload and does not check the signature. That is enough
  // for an id_token that arrives directly from the token endpoint over TLS in
  // a request authenticated with the client credential (OIDC Core 3.1.3.7).
  // Never use this for a token that came through the browser or a third party.
  TJwtPayload = class
  private
    class function PayloadPart(const Jwt: string): string; static;
    class function DecodePart(const Part: string): string; static;
    class function ParseObject(const Json: string): TJSONObject; static;

  public
    // The caller owns the returned object.
    class function Decode(const Jwt: string): TJSONObject; static;
  end;

implementation

uses
  System.NetEncoding,
  MCPAuth.Upstream.Exceptions;

const
  JwtPartCount = 3;
  PayloadIndex = 1;

resourcestring
  JwtMalformed = 'The token is not a well-formed JWT';
  JwtPayloadMalformed = 'The JWT payload is not a JSON object';

{ TJwtPayload }

class function TJwtPayload.Decode(const Jwt: string): TJSONObject;
begin
  const Payload = PayloadPart(Jwt);
  const Json = DecodePart(Payload);

  Result := ParseObject(Json);
end;

class function TJwtPayload.PayloadPart(const Jwt: string): string;
begin
  const Parts = Jwt.Split(['.']);

  const HasThreeParts = (Length(Parts) = JwtPartCount);
  if not HasThreeParts then
    raise EUpstreamTokenMalformed.Create(JwtMalformed);

  Result := Parts[PayloadIndex];
  if Result.IsEmpty then
    raise EUpstreamTokenMalformed.Create(JwtMalformed);
end;

class function TJwtPayload.DecodePart(const Part: string): string;
begin
  try
    const PartBytes = TNetEncoding.Base64URL.DecodeStringToBytes(Part);
    Result := TEncoding.UTF8.GetString(PartBytes);
  except
    on EEncodingError do
      raise EUpstreamTokenMalformed.Create(JwtMalformed);
  end;
end;

class function TJwtPayload.ParseObject(const Json: string): TJSONObject;
begin
  const Value = TJSONObject.ParseJSONValue(Json);

  const IsObject = (Value is TJSONObject);
  if not IsObject then
  begin
    Value.Free;
    raise EUpstreamTokenMalformed.Create(JwtPayloadMalformed);
  end;

  Result := TJSONObject(Value);
end;

end.
