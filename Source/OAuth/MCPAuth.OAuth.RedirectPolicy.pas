unit MCPAuth.OAuth.RedirectPolicy;

interface

type
  TRedirectPolicy = class
  private type
    TParsedUri = record
      Scheme: string;
      Host: string;
      Port: string;
      Path: string;
    end;

  private
    FExtraAllowed: TArray<string>;

    class function TryParse(const Uri: string; out Parsed: TParsedUri): Boolean; static;
    class function HasForbiddenCharacters(const Uri: string): Boolean; static;
    class function TrySplitAuthority(const Authority: string; out Host, Port: string): Boolean; static;
    class function IsPortValid(const Port: string): Boolean; static;
    class function IsClaudeCallback(const Parsed: TParsedUri): Boolean; static;
    class function IsLoopback(const Parsed: TParsedUri): Boolean; static;

    function IsExtraAllowed(const Uri: string; const Parsed: TParsedUri): Boolean;

  public
    constructor Create(const ExtraAllowed: TArray<string>);

    function IsAllowed(const Uri: string): Boolean;
  end;

implementation

uses
  System.SysUtils;

const
  SchemeSeparator = '://';
  SchemeHttps = 'https';
  SchemeHttp = 'http';
  DefaultHttpsPort = '443';
  ClaudeCallbackPath = '/api/mcp/auth_callback';
  ClaudeAiHost = 'claude.ai';
  ClaudeComHost = 'claude.com';
  LocalhostName = 'localhost';
  LoopbackAddress = '127.0.0.1';
  MaxPort = 65535;
  MaxPortLength = 5;
  LastControlCharacter = 32;
  DeleteCharacter = 127;

{ TRedirectPolicy }

constructor TRedirectPolicy.Create(const ExtraAllowed: TArray<string>);
begin
  inherited Create;

  FExtraAllowed := ExtraAllowed;
end;

function TRedirectPolicy.IsAllowed(const Uri: string): Boolean;
begin
  var Parsed: TParsedUri;
  const IsParsable = TryParse(Uri, Parsed);
  if not IsParsable then
    Exit(False);

  const IsDefaultAllowed = (IsClaudeCallback(Parsed) or IsLoopback(Parsed));

  Result := (IsDefaultAllowed or IsExtraAllowed(Uri, Parsed));
end;

class function TRedirectPolicy.TryParse(const Uri: string; out Parsed: TParsedUri): Boolean;
begin
  Parsed := Default(TParsedUri);

  if HasForbiddenCharacters(Uri) then
    Exit(False);

  const SeparatorIndex = Uri.IndexOf(SchemeSeparator);
  const HasScheme = (SeparatorIndex > 0);
  if not HasScheme then
    Exit(False);

  Parsed.Scheme := Uri.Substring(0, SeparatorIndex).ToLowerInvariant;

  const Remainder = Uri.Substring(SeparatorIndex + SchemeSeparator.Length);
  const PathStart = Remainder.IndexOf('/');
  const HasPath = (PathStart >= 0);
  if not HasPath then
    Exit(False);

  Parsed.Path := Remainder.Substring(PathStart);

  Result := TrySplitAuthority(Remainder.Substring(0, PathStart), Parsed.Host, Parsed.Port);
end;

class function TRedirectPolicy.HasForbiddenCharacters(const Uri: string): Boolean;
begin
  // Browsers and parsers treat a backslash and whitespace differently, which makes them a way to smuggle in another host.
  for var Character in Uri do
  begin
    const IsFragmentStart = (Character = '#');
    const IsBackslash = (Character = '\');
    const IsControlOrSpace = (Ord(Character) <= LastControlCharacter) or (Ord(Character) = DeleteCharacter);
    if IsFragmentStart or IsBackslash or IsControlOrSpace then
      Exit(True);
  end;

  Result := False;
end;

class function TRedirectPolicy.TrySplitAuthority(const Authority: string; out Host, Port: string): Boolean;
begin
  Host := '';
  Port := '';

  const HasUserInfo = Authority.Contains('@');
  if HasUserInfo then
    Exit(False);

  const PortSeparator = Authority.IndexOf(':');
  const HasPort = (PortSeparator >= 0);
  if HasPort then
  begin
    Host := Authority.Substring(0, PortSeparator).ToLowerInvariant;
    Port := Authority.Substring(PortSeparator + 1);
    if not IsPortValid(Port) then
      Exit(False);
  end
  else
  begin
    Host := Authority.ToLowerInvariant;
  end;

  Result := not Host.IsEmpty;
end;

class function TRedirectPolicy.IsPortValid(const Port: string): Boolean;
begin
  const HasValidLength = (Port.Length >= 1) and (Port.Length <= MaxPortLength);
  if not HasValidLength then
    Exit(False);

  for var Character in Port do
  begin
    const IsDigit = CharInSet(Character, ['0'..'9']);
    if not IsDigit then
      Exit(False);
  end;

  const Number = Port.ToInteger;

  Result := (Number >= 1) and (Number <= MaxPort);
end;

class function TRedirectPolicy.IsClaudeCallback(const Parsed: TParsedUri): Boolean;
begin
  const IsClaudeHost = (Parsed.Host = ClaudeAiHost) or (Parsed.Host = ClaudeComHost);
  const IsDefaultPort = (Parsed.Port.IsEmpty or (Parsed.Port = DefaultHttpsPort));

  Result := (Parsed.Scheme = SchemeHttps) and IsClaudeHost and IsDefaultPort and (Parsed.Path = ClaudeCallbackPath);
end;

class function TRedirectPolicy.IsLoopback(const Parsed: TParsedUri): Boolean;
begin
  const IsLoopbackHost = (Parsed.Host = LocalhostName) or (Parsed.Host = LoopbackAddress);

  Result := (Parsed.Scheme = SchemeHttp) and IsLoopbackHost;
end;

function TRedirectPolicy.IsExtraAllowed(const Uri: string; const Parsed: TParsedUri): Boolean;
begin
  const IsHttps = (Parsed.Scheme = SchemeHttps);
  if not IsHttps then
    Exit(False);

  for var Allowed in FExtraAllowed do
  begin
    if Uri = Allowed then
      Exit(True);
  end;

  Result := False;
end;

end.
