unit MCPAuth.Web.Types;

interface

uses
  System.Classes,
  System.JSON,
  Spring.Collections;

type
  TWebSession = record
    IdHash: string;
    UserId: string;
    CsrfToken: string;
    ExpiresAtUtc: TDateTime;
  end;

  // A request independent of the HTTP server. Query and Body hold the raw, still encoded text.
  // Headers and Cookies may be nil when the request has none.
  TWebRequest = record
  private
    class function FindField(const Encoded, Name: string): string; static;
    class function DecodeComponent(const Encoded: string): string; static;
    class function TryReadEscapedByte(const Encoded: string; const Index: Integer; out Value: Byte): Boolean; static;
    class function TryHexDigit(const Digit: Char; out Value: Integer): Boolean; static;
    class procedure AppendText(const Stream: TBytesStream; const Text: string); static;

  public
    Method: string;
    Path: string;
    Query: string;
    Body: string;
    ContentType: string;
    RemoteAddress: string;
    Headers: IDictionary<string, string>;
    Cookies: IDictionary<string, string>;

    // Fields are application/x-www-form-urlencoded (UTF-8, '+' is a space); the first occurrence wins
    // and an absent field reads as empty.
    function QueryParam(const Name: string): string;
    function FormField(const Name: string): string;
    function TryGetCookie(const Name: string; out Value: string): Boolean;

    // The caller owns the returned object; nil when the body is not a JSON object.
    function JsonBody: TJSONObject;
  end;

  TWebResponse = record
    StatusCode: Integer;
    ContentType: string;
    Body: string;
    Location: string;
    SetCookies: TArray<string>;
    ExtraHeaders: TArray<TPair<string, string>>;

    class function Html(const StatusCode: Integer; const Body: string): TWebResponse; static;
    class function Json(const StatusCode: Integer; const Body: string): TWebResponse; static;
    class function Redirect(const Location: string): TWebResponse; static;

    // A JSON error body {"error", "error_description"}; the description is left out when empty.
    class function Error(const StatusCode: Integer; const ErrorCode, Description: string): TWebResponse; static;

    procedure AddHeader(const Name, Value: string);
    procedure AddCookie(const Cookie: string);
  end;

  TWebHandler = reference to function(const Request: TWebRequest): TWebResponse;

implementation

uses
  System.SysUtils;

const
  FieldSeparator = '&';
  ValueSeparator = '=';
  EscapeCharacter = '%';
  EncodedSpace = '+';
  SpaceByte = 32;
  HtmlContentType = 'text/html; charset=utf-8';
  JsonContentType = 'application/json; charset=utf-8';
  StatusFound = 302;

{ TWebRequest }

class function TWebRequest.FindField(const Encoded, Name: string): string;
begin
  for var Field in Encoded.Split([FieldSeparator]) do
  begin
    const SeparatorIndex = Field.IndexOf(ValueSeparator);
    const HasValue = (SeparatorIndex >= 0);

    var EncodedName := Field;
    var EncodedValue := '';
    if HasValue then
    begin
      EncodedName := Field.Substring(0, SeparatorIndex);
      EncodedValue := Field.Substring(SeparatorIndex + 1);
    end;

    const IsRequestedField = (DecodeComponent(EncodedName) = Name);
    if IsRequestedField then
      Exit(DecodeComponent(EncodedValue));
  end;

  Result := '';
end;

class function TWebRequest.DecodeComponent(const Encoded: string): string;
begin
  // Escapes are collected as bytes first, so a multi-byte UTF-8 character spread over several escapes decodes as one.
  // A malformed escape stays as literal text instead of failing the request.
  const Stream = TBytesStream.Create;
  try
    var RunStart := 1;
    var Index := 1;
    while Index <= Encoded.Length do
    begin
      var EscapedByte: Byte := 0;
      const IsSpace = (Encoded[Index] = EncodedSpace);
      const IsEscape = ((Encoded[Index] = EscapeCharacter) and TryReadEscapedByte(Encoded, Index, EscapedByte));

      if IsSpace or IsEscape then
      begin
        AppendText(Stream, Copy(Encoded, RunStart, Index - RunStart));
        if IsSpace then
        begin
          Stream.WriteData(Byte(SpaceByte));
          Inc(Index);
        end
        else
        begin
          Stream.WriteData(EscapedByte);
          Inc(Index, 3);
        end;
        RunStart := Index;
      end
      else
      begin
        Inc(Index);
      end;
    end;
    AppendText(Stream, Copy(Encoded, RunStart, MaxInt));

    const Bytes = Copy(Stream.Bytes, 0, Stream.Size);
    Result := TEncoding.UTF8.GetString(Bytes);
  finally
    Stream.Free;
  end;
end;

class function TWebRequest.TryReadEscapedByte(const Encoded: string; const Index: Integer; out Value: Byte): Boolean;
begin
  Value := 0;

  const HasTwoDigits = (Index + 2 <= Encoded.Length);
  if not HasTwoDigits then
    Exit(False);

  var High: Integer;
  var Low: Integer;
  Result := TryHexDigit(Encoded[Index + 1], High) and TryHexDigit(Encoded[Index + 2], Low);
  if Result then
    Value := Byte((High shl 4) or Low);
end;

class function TWebRequest.TryHexDigit(const Digit: Char; out Value: Integer): Boolean;
begin
  Result := True;
  case Digit of
    '0'..'9' : Value := Ord(Digit) - Ord('0');
    'a'..'f' : Value := Ord(Digit) - Ord('a') + 10;
    'A'..'F' : Value := Ord(Digit) - Ord('A') + 10;
  else
    Value := 0;
    Result := False;
  end;
end;

class procedure TWebRequest.AppendText(const Stream: TBytesStream; const Text: string);
begin
  if Text.IsEmpty then
    Exit;

  const Bytes = TEncoding.UTF8.GetBytes(Text);
  Stream.WriteBuffer(Bytes, Length(Bytes));
end;

function TWebRequest.QueryParam(const Name: string): string;
begin
  Result := FindField(Query, Name);
end;

function TWebRequest.FormField(const Name: string): string;
begin
  Result := FindField(Body, Name);
end;

function TWebRequest.TryGetCookie(const Name: string; out Value: string): Boolean;
begin
  Value := '';
  Result := Assigned(Cookies) and Cookies.TryGetValue(Name, Value);
end;

function TWebRequest.JsonBody: TJSONObject;
begin
  const Value = TJSONObject.ParseJSONValue(Body);
  if Value is TJSONObject then
    Exit(TJSONObject(Value));

  Value.Free;
  Result := nil;
end;

{ TWebResponse }

class function TWebResponse.Html(const StatusCode: Integer; const Body: string): TWebResponse;
begin
  Result := Default(TWebResponse);
  Result.StatusCode  := StatusCode;
  Result.ContentType := HtmlContentType;
  Result.Body        := Body;
end;

class function TWebResponse.Json(const StatusCode: Integer; const Body: string): TWebResponse;
begin
  Result := Default(TWebResponse);
  Result.StatusCode  := StatusCode;
  Result.ContentType := JsonContentType;
  Result.Body        := Body;
end;

class function TWebResponse.Redirect(const Location: string): TWebResponse;
begin
  Result := Default(TWebResponse);
  Result.StatusCode := StatusFound;
  Result.Location   := Location;
end;

class function TWebResponse.Error(const StatusCode: Integer; const ErrorCode, Description: string): TWebResponse;
begin
  const ErrorObject = TJSONObject.Create;
  try
    ErrorObject.AddPair('error', ErrorCode);
    if not Description.IsEmpty then
      ErrorObject.AddPair('error_description', Description);

    Result := Json(StatusCode, ErrorObject.ToJSON);
  finally
    ErrorObject.Free;
  end;
end;

procedure TWebResponse.AddHeader(const Name, Value: string);
begin
  ExtraHeaders := ExtraHeaders + [TPair<string, string>.Create(Name, Value)];
end;

procedure TWebResponse.AddCookie(const Cookie: string);
begin
  SetCookies := SetCookies + [Cookie];
end;

end.
