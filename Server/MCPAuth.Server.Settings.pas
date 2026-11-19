unit MCPAuth.Server.Settings;

interface

uses
  System.SysUtils,
  MCPAuth.Secret.Interfaces,
  MCPAuth.Secret.KeyRing;

type
  {$SCOPEDENUMS ON}
  TServerStoreKind = (Memory, Postgres);
  {$SCOPEDENUMS OFF}

  // The settings of the auth server program, read from MCPAUTH_* environment variables.
  // A missing or invalid variable raises EServerConfiguration that names the variable, never its value.
  TServerSettings = record
  private
    class function ReadRequired(const ReadVariable: TVariableReader; const Name: string): string; static;
    class function ReadOptional(const ReadVariable: TVariableReader; const Name, DefaultValue: string): string; static;
    class function ReadPort(const ReadVariable: TVariableReader; const Name: string; const DefaultPort: Word): Word; static;
    class function ReadFlag(const ReadVariable: TVariableReader; const Name: string): Boolean; static;
    class function ReadStore(const ReadVariable: TVariableReader): TServerStoreKind; static;
    class function ReadKeyRing(const ReadVariable: TVariableReader): IKeyRing; static;
    class function ReadFolder(const ReadVariable: TVariableReader; const Name, ExecutableFolder, FolderName, Marker: string): string; static;
    class function FindFolder(const ExecutableFolder, FolderName, Marker: string): string; static;

    procedure ReadMicrosoft(const ReadVariable: TVariableReader);

  public
    Issuer: string;
    PublicBind: string;
    PublicPort: Word;
    InternalBind: string;
    InternalPort: Word;
    RegistryPath: string;
    Store: TServerStoreKind;
    DatabaseConnection: string;
    MigrationsPath: string;
    ProjectTemplatesPath: string;
    LibraryTemplatesPath: string;
    MicrosoftClientId: string;
    MicrosoftCertificatePath: string;
    MicrosoftClientSecret: string;
    AllowHttpResources: Boolean;
    KeyRing: IKeyRing;
    Warnings: TArray<string>;

    class function FromEnvironment: TServerSettings; static;

    // ExecutableFolder is the base of the default template and migration folders.
    class function FromVariables(const ReadVariable: TVariableReader; const ExecutableFolder: string): TServerSettings; static;

    // Active with a client id plus a certificate or a client secret.
    function IsMicrosoftActive: Boolean;
    function UsesMicrosoftCertificate: Boolean;
  end;

implementation

uses
  System.IOUtils,
  MCPAuth.Server.Exceptions;

const
  KeyRingPrefix = 'MCPAUTH';
  IssuerVariable = 'MCPAUTH_ISSUER';
  PublicBindVariable = 'MCPAUTH_PUBLIC_BIND';
  PublicPortVariable = 'MCPAUTH_PUBLIC_PORT';
  InternalBindVariable = 'MCPAUTH_INTERNAL_BIND';
  InternalPortVariable = 'MCPAUTH_INTERNAL_PORT';
  RegistryVariable = 'MCPAUTH_REGISTRY';
  StoreVariable = 'MCPAUTH_STORE';
  DatabaseVariable = 'MCPAUTH_DB';
  MigrationsVariable = 'MCPAUTH_MIGRATIONS';
  ProjectTemplatesVariable = 'MCPAUTH_TEMPLATES';
  LibraryTemplatesVariable = 'MCPAUTH_LIBRARY_TEMPLATES';
  MicrosoftClientIdVariable = 'MCPAUTH_MICROSOFT_CLIENT_ID';
  MicrosoftCertificateVariable = 'MCPAUTH_MICROSOFT_CERTIFICATE';
  MicrosoftClientSecretVariable = 'MCPAUTH_MICROSOFT_CLIENT_SECRET';
  AllowHttpResourcesVariable = 'MCPAUTH_ALLOW_HTTP_RESOURCES';
  MasterKeyVariable = 'MCPAUTH_MASTER_KEY';

  LoopbackAddress = '127.0.0.1';
  DefaultPublicPort = 8100;
  DefaultInternalPort = 8101;
  MemoryStoreName = 'memory';
  PostgresStoreName = 'postgres';
  TemplatesFolder = 'templates';
  TemplatesMarker = 'layout.html';
  MigrationsFolder = 'migrations';
  MigrationsMarker = 'postgres';
  TrueValues: array[0..2] of string = ('1', 'true', 'yes');
  FalseValues: array[0..3] of string = ('', '0', 'false', 'no');

resourcestring
  MissingVariable = 'Missing environment variable %s';
  InvalidVariable = 'Invalid value in environment variable %s';
  CertificateWinsOverSecret = 'Both %s and %s are set; the certificate is used';

{ TServerSettings }

class function TServerSettings.FromEnvironment: TServerSettings;
begin
  const ExecutableFolder = TPath.GetDirectoryName(ParamStr(0));

  Result := FromVariables(
    function(const Name: string): string
    begin
      Result := GetEnvironmentVariable(Name);
    end,
    ExecutableFolder);
end;

class function TServerSettings.FromVariables(const ReadVariable: TVariableReader; const ExecutableFolder: string): TServerSettings;
begin
  Result := Default(TServerSettings);

  const Issuer = ReadRequired(ReadVariable, IssuerVariable);
  Result.Issuer       := Issuer.TrimRight(['/']);
  Result.PublicBind   := ReadOptional(ReadVariable, PublicBindVariable, LoopbackAddress);
  Result.PublicPort   := ReadPort(ReadVariable, PublicPortVariable, DefaultPublicPort);
  Result.InternalBind := ReadOptional(ReadVariable, InternalBindVariable, LoopbackAddress);
  Result.InternalPort := ReadPort(ReadVariable, InternalPortVariable, DefaultInternalPort);
  Result.RegistryPath := ReadRequired(ReadVariable, RegistryVariable);
  Result.Store        := ReadStore(ReadVariable);

  const UsesPostgres = (Result.Store = TServerStoreKind.Postgres);
  if UsesPostgres then
    Result.DatabaseConnection := ReadRequired(ReadVariable, DatabaseVariable);

  Result.MigrationsPath       := ReadFolder(ReadVariable, MigrationsVariable, ExecutableFolder, MigrationsFolder, MigrationsMarker);
  Result.ProjectTemplatesPath := ReadOptional(ReadVariable, ProjectTemplatesVariable, '');
  Result.LibraryTemplatesPath := ReadFolder(ReadVariable, LibraryTemplatesVariable, ExecutableFolder, TemplatesFolder, TemplatesMarker);
  Result.AllowHttpResources   := ReadFlag(ReadVariable, AllowHttpResourcesVariable);

  Result.ReadMicrosoft(ReadVariable);
  Result.KeyRing := ReadKeyRing(ReadVariable);
end;

class function TServerSettings.ReadRequired(const ReadVariable: TVariableReader; const Name: string): string;
begin
  Result := ReadVariable(Name).Trim;
  if Result.IsEmpty then
    raise EServerConfiguration.CreateFmt(MissingVariable, [Name]);
end;

class function TServerSettings.ReadOptional(const ReadVariable: TVariableReader; const Name, DefaultValue: string): string;
begin
  Result := ReadVariable(Name).Trim;
  if Result.IsEmpty then
    Result := DefaultValue;
end;

class function TServerSettings.ReadPort(const ReadVariable: TVariableReader; const Name: string; const DefaultPort: Word): Word;
begin
  const Value = ReadVariable(Name).Trim;
  if Value.IsEmpty then
    Exit(DefaultPort);

  var Port: Integer;
  const IsValidPort = (TryStrToInt(Value, Port) and (Port >= Low(Word)) and (Port <= High(Word)));
  if not IsValidPort then
    raise EServerConfiguration.CreateFmt(InvalidVariable, [Name]);

  Result := Port;
end;

class function TServerSettings.ReadFlag(const ReadVariable: TVariableReader; const Name: string): Boolean;
begin
  const Value = ReadVariable(Name).Trim.ToLower;

  for var TrueValue in TrueValues do
  begin
    if Value = TrueValue then
      Exit(True);
  end;

  for var FalseValue in FalseValues do
  begin
    if Value = FalseValue then
      Exit(False);
  end;

  raise EServerConfiguration.CreateFmt(InvalidVariable, [Name]);
end;

class function TServerSettings.ReadStore(const ReadVariable: TVariableReader): TServerStoreKind;
begin
  const Value = ReadOptional(ReadVariable, StoreVariable, MemoryStoreName).ToLower;

  if Value = MemoryStoreName then
    Result := TServerStoreKind.Memory
  else if Value = PostgresStoreName then
    Result := TServerStoreKind.Postgres
  else
    raise EServerConfiguration.CreateFmt(InvalidVariable, [StoreVariable]);
end;

class function TServerSettings.ReadKeyRing(const ReadVariable: TVariableReader): IKeyRing;
begin
  ReadRequired(ReadVariable, MasterKeyVariable);

  try
    Result := TKeyRing.FromVariables(KeyRingPrefix, ReadVariable);
  except
    // The key ring names the faulty variable or key id, never a key.
    on E: ESecretConfigurationError do
      raise EServerConfiguration.Create(E.Message);
  end;
end;

class function TServerSettings.ReadFolder(const ReadVariable: TVariableReader; const Name, ExecutableFolder, FolderName, Marker: string): string;
begin
  Result := ReadVariable(Name).Trim;
  if Result.IsEmpty then
    Result := FindFolder(ExecutableFolder, FolderName, Marker);
end;

class function TServerSettings.FindFolder(const ExecutableFolder, FolderName, Marker: string): string;
begin
  // Next to the executable in a deployment. A program started from the build output (bin/<platform>/<config>)
  // finds the folder of the repository higher up instead.
  var Folder := ExecutableFolder;
  while not Folder.IsEmpty do
  begin
    const Candidate = TPath.Combine(Folder, FolderName);
    const MarkerPath = TPath.Combine(Candidate, Marker);
    const HasMarker = (TFile.Exists(MarkerPath) or TDirectory.Exists(MarkerPath));
    if HasMarker then
      Exit(Candidate);

    const Parent = TPath.GetDirectoryName(Folder);
    const IsRoot = (Parent = Folder);
    if IsRoot then
      Break;

    Folder := Parent;
  end;

  Result := TPath.Combine(ExecutableFolder, FolderName);
end;

procedure TServerSettings.ReadMicrosoft(const ReadVariable: TVariableReader);
begin
  MicrosoftClientId        := ReadOptional(ReadVariable, MicrosoftClientIdVariable, '');
  MicrosoftCertificatePath := ReadOptional(ReadVariable, MicrosoftCertificateVariable, '');
  MicrosoftClientSecret    := ReadOptional(ReadVariable, MicrosoftClientSecretVariable, '');

  const HasBothCredentials = (not MicrosoftCertificatePath.IsEmpty and not MicrosoftClientSecret.IsEmpty);
  if HasBothCredentials then
  begin
    Warnings := Warnings + [Format(CertificateWinsOverSecret, [MicrosoftCertificateVariable, MicrosoftClientSecretVariable])];
    MicrosoftClientSecret := '';
  end;
end;

function TServerSettings.IsMicrosoftActive: Boolean;
begin
  const HasCredential = (not MicrosoftCertificatePath.IsEmpty or not MicrosoftClientSecret.IsEmpty);
  Result := (not MicrosoftClientId.IsEmpty and HasCredential);
end;

function TServerSettings.UsesMicrosoftCertificate: Boolean;
begin
  Result := (IsMicrosoftActive and not MicrosoftCertificatePath.IsEmpty);
end;

end.
