unit MCPAuth.Upstream.FormEncoding;

interface

uses
  Spring.Collections;

type
  // application/x-www-form-urlencoded, used for token request bodies and for
  // the query of an authorization URL.
  TFormEncoding = class
  private
    class function EncodeField(const Field: TPair<string, string>): string; static;

  public
    class function Encode(const Fields: TArray<TPair<string, string>>): string; static;
  end;

implementation

uses
  System.SysUtils,
  System.NetEncoding;

{ TFormEncoding }

class function TFormEncoding.Encode(const Fields: TArray<TPair<string, string>>): string;
begin
  var EncodedFields: TArray<string>;
  SetLength(EncodedFields, Length(Fields));
  for var Index := 0 to High(Fields) do
  begin
    EncodedFields[Index] := EncodeField(Fields[Index]);
  end;

  Result := string.Join('&', EncodedFields);
end;

class function TFormEncoding.EncodeField(const Field: TPair<string, string>): string;
begin
  const EncodedName = TNetEncoding.URL.EncodeForm(Field.Key);
  const EncodedValue = TNetEncoding.URL.EncodeForm(Field.Value);

  Result := Format('%s=%s', [EncodedName, EncodedValue]);
end;

end.
