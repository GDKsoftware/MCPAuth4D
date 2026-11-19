unit MCPAuth.Server.Composition;

interface

uses
  System.SysUtils,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Secret.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Store.FireDAC.PgDriver,
  MCPAuth.Resource.Interfaces,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.Identity.Interfaces,
  MCPAuth.OAuth.Settings,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.Web.Session.Interfaces,
  MCPAuth.Web.Page.Interfaces,
  MCPAuth.Web.Router,
  MCPAuth.Web.Controller.OAuth,
  MCPAuth.Web.Controller.Account,
  MCPAuth.Internal.Controller,
  MCPAuth.Web.Server.Indy,
  MCPAuth.Server.Settings,
  MCPAuth.Server.Maintenance;

type
  // The composition root of the auth server program: builds the store, the registry, the upstream providers,
  // the authorization server, the controllers and the public and internal listeners, and owns them all.
  // Start raises EServerConfiguration for a configuration that cannot work, before any listener opens.
  TServerComposition = class
  private
    FSettings: TServerSettings;
    FClock: IClock;
    FPgDriver: TFireDACPgDriver;
    FStores: TStoreSet;
    FRegistry: IResourceRegistry;
    FProviders: IUpstreamProviders;
    FAccounts: ILinkedAccounts;
    FAuthSettings: TMCPAuthSettings;
    FTokens: ITokenGenerator;
    FAuthorizationServer: IAuthorizationServer;
    FSessions: IWebSessions;
    FPages: IPageRenderer;
    FOAuthController: TOAuthController;
    FAccountController: TAccountController;
    FInternalController: TInternalController;
    FPublicRouter: TWebRouter;
    FInternalRouter: TWebRouter;
    FPublicHost: TMCPAuthWebServer;
    FInternalHost: TMCPAuthWebServer;
    FMaintenance: TServerMaintenance;
    FIsRunning: Boolean;

    class function WithDatabaseTimeouts(const ConnectionString: string): string; static;

    procedure BuildStores;
    procedure BuildPostgresStores;
    procedure BuildRegistry;
    procedure BuildProviders;
    function BuildMicrosoftProvider: IUpstreamProvider;
    procedure GuardRegistryProviders;
    procedure GuardTemplates;
    procedure BuildServices;
    procedure BuildRouters;
    procedure StartListeners;
    function CreateHost(const Router: TWebRouter; const Port: Word; const BindAddress: string): TMCPAuthWebServer;
    procedure LogStarted;
    procedure Restart;

  public
    constructor Create(const Settings: TServerSettings); overload;
    constructor Create(const Settings: TServerSettings; const Clock: IClock); overload;
    destructor Destroy; override;

    procedure Start;
    procedure Stop;
    function IsRunning: Boolean;

    // The ports the listeners actually use; they differ from the settings when those were 0.
    function PublicPort: Word;
    function InternalPort: Word;
  end;

implementation

uses
  System.IOUtils,
  System.StrUtils,
  Spring.Collections,
  MCPServer.Logger,
  MCPAuth.Clock,
  MCPAuth.Secret.Token,
  MCPAuth.Secret.AesGcm,
  MCPAuth.Store.Memory,
  MCPAuth.Store.FireDAC,
  MCPAuth.Store.FireDAC.Interfaces,
  MCPAuth.Store.FireDAC.ConnectionFactory,
  MCPAuth.Store.FireDAC.Migrations,
  MCPAuth.Resource.Types,
  MCPAuth.Resource.Registry.Json,
  MCPAuth.Upstream.Http,
  MCPAuth.Upstream.Providers,
  MCPAuth.Upstream.Microsoft,
  MCPAuth.Upstream.Credential.Secret,
  MCPAuth.Upstream.Credential.Certificate,
  MCPAuth.Identity.Accounts,
  MCPAuth.Identity.Access.AllowAll,
  MCPAuth.OAuth.Server,
  MCPAuth.Web.Session,
  MCPAuth.Web.Page.WebStencils,
  MCPAuth.Server.Exceptions;

const
  MicrosoftProviderName = 'microsoft';
  PostgresDialect = 'postgres';
  HttpsScheme = 'https://';
  LayoutTemplate = 'layout.html';
  PgAdvancedParameter = 'PGAdvanced=';
  // Without these a query that waits on a lock or a stuck connection would hold a request thread forever.
  DatabaseTimeouts = 'PGAdvanced=options=-c statement_timeout=30000 -c lock_timeout=10000';

resourcestring
  ProviderNotActive = 'Resource %s uses provider %s, which is not configured';
  NoProviderActive = 'No upstream provider is configured; set MCPAUTH_MICROSOFT_CLIENT_ID with a certificate or a client secret';
  LibraryTemplatesMissing = 'The library templates are not found; set MCPAUTH_LIBRARY_TEMPLATES';
  ProjectTemplatesMissing = 'The folder in MCPAUTH_TEMPLATES does not exist';
  StartedFormat = 'MCPAuth server started: issuer %s, public listener %s:%d, internal listener %s:%d, store %s';
  ProviderActiveFormat = 'Upstream provider %s is active (%s)';
  CertificateCredential = 'certificate';
  SecretCredential = 'client secret';

{ TServerComposition }

class function TServerComposition.WithDatabaseTimeouts(const ConnectionString: string): string;
begin
  const HasOwnAdvancedOptions = ContainsText(ConnectionString, PgAdvancedParameter);
  if HasOwnAdvancedOptions then
    Exit(ConnectionString);

  Result := Format('%s;%s', [ConnectionString.TrimRight([';']), DatabaseTimeouts]);
end;

constructor TServerComposition.Create(const Settings: TServerSettings);
begin
  Create(Settings, TSystemClock.Create);
end;

constructor TServerComposition.Create(const Settings: TServerSettings; const Clock: IClock);
begin
  inherited Create;

  FSettings := Settings;
  FClock := Clock;
end;

destructor TServerComposition.Destroy;
begin
  Stop;

  FPublicHost.Free;
  FInternalHost.Free;
  FMaintenance.Free;

  // The routers hold handlers that call into the controllers, so they go first.
  FPublicRouter.Free;
  FInternalRouter.Free;
  FOAuthController.Free;
  FAccountController.Free;
  FInternalController.Free;

  FPages := nil;
  FSessions := nil;
  FAuthorizationServer := nil;
  FAccounts := nil;
  FProviders := nil;
  FRegistry := nil;
  FStores := Default(TStoreSet);

  // The driver must outlive every connection of the stores.
  FPgDriver.Free;
  inherited Destroy;
end;

procedure TServerComposition.Start;
begin
  if FIsRunning then
    Exit;

  const WasStartedBefore = Assigned(FMaintenance);
  if WasStartedBefore then
  begin
    Restart;
    Exit;
  end;

  for var Warning in FSettings.Warnings do
  begin
    TLogger.Warning(Warning);
  end;

  BuildRegistry;
  BuildProviders;
  GuardRegistryProviders;
  GuardTemplates;
  BuildStores;
  BuildServices;
  BuildRouters;
  StartListeners;

  FMaintenance := TServerMaintenance.Create(FStores, FClock);
  FMaintenance.Start;

  FIsRunning := True;
  LogStarted;
end;

procedure TServerComposition.BuildRegistry;
begin
  FRegistry := TJsonResourceRegistry.FromFile(FSettings.RegistryPath, FSettings.AllowHttpResources);
end;

procedure TServerComposition.BuildProviders;
begin
  const Providers = TCollections.CreateList<IUpstreamProvider>;

  if FSettings.IsMicrosoftActive then
    Providers.Add(BuildMicrosoftProvider);

  FProviders := TUpstreamProviders.Create(Providers.ToArray);
end;

function TServerComposition.BuildMicrosoftProvider: IUpstreamProvider;
begin
  var Credential: IClientCredential;
  var CredentialKind: string;
  if FSettings.UsesMicrosoftCertificate then
  begin
    Credential := TCertificateCredential.FromPemFile(FSettings.MicrosoftClientId, FSettings.MicrosoftCertificatePath);
    CredentialKind := CertificateCredential;
  end
  else
  begin
    Credential := TClientSecretCredential.Create(FSettings.MicrosoftClientId, FSettings.MicrosoftClientSecret);
    CredentialKind := SecretCredential;
  end;

  const Scopes = FRegistry.ScopesForProvider(MicrosoftProviderName);
  Result := TMicrosoftUpstreamProvider.Create(FSettings.MicrosoftClientId, Credential, Scopes, TUpstreamHttp.Create);
  TLogger.Info(ProviderActiveFormat, [MicrosoftProviderName, CredentialKind]);
end;

procedure TServerComposition.GuardRegistryProviders;
begin
  for var Resource in FRegistry.All do
  begin
    for var ResourceProvider in Resource.Providers do
    begin
      var Provider: IUpstreamProvider;
      const IsActive = FProviders.TryGet(ResourceProvider.Provider, Provider);
      if not IsActive then
        raise EServerConfiguration.CreateFmt(ProviderNotActive, [Resource.ResourceUri, ResourceProvider.Provider]);
    end;
  end;

  const HasNoProvider = (Length(FProviders.Names) = 0);
  if HasNoProvider then
    raise EServerConfiguration.Create(NoProviderActive);
end;

procedure TServerComposition.GuardTemplates;
begin
  const HasLibraryLayout = TFile.Exists(TPath.Combine(FSettings.LibraryTemplatesPath, LayoutTemplate));
  if not HasLibraryLayout then
    raise EServerConfiguration.Create(LibraryTemplatesMissing);

  const HasProjectTemplates = not FSettings.ProjectTemplatesPath.IsEmpty;
  const IsProjectTemplatesMissing = (HasProjectTemplates and not TDirectory.Exists(FSettings.ProjectTemplatesPath));
  if IsProjectTemplatesMissing then
    raise EServerConfiguration.Create(ProjectTemplatesMissing);
end;

procedure TServerComposition.BuildStores;
begin
  case FSettings.Store of
    TServerStoreKind.Memory   : FStores := TMemoryStore.CreateSet(FClock);
    TServerStoreKind.Postgres : BuildPostgresStores;
  else
    raise ENotSupportedException.CreateFmt('Unsupported store kind: %d', [Ord(FSettings.Store)]);
  end;
end;

procedure TServerComposition.BuildPostgresStores;
begin
  FPgDriver := TFireDACPgDriver.Create;

  const ConnectionString = WithDatabaseTimeouts(FSettings.DatabaseConnection);
  const Factory: IFireDACConnectionFactory = TFireDACConnectionFactory.Create(ConnectionString);
  TFireDACMigrations.Apply(Factory, PostgresDialect, FSettings.MigrationsPath);

  FStores := TFireDACStore.CreateSet(Factory, FClock);
end;

procedure TServerComposition.BuildServices;
begin
  FAuthSettings := TMCPAuthSettings.Defaults(FSettings.Issuer);
  FAuthSettings.ProjectTemplatesPath := FSettings.ProjectTemplatesPath;
  FAuthSettings.LibraryTemplatesPath := FSettings.LibraryTemplatesPath;
  FAuthSettings.SecureCookies        := StartsText(HttpsScheme, FSettings.Issuer);

  const Protector = TAesGcmProtector.Create(FSettings.KeyRing);
  FTokens := TTokenGenerator.Create;
  FAccounts := TLinkedAccounts.Create(FStores.Users, FStores.LinkedAccounts, Protector, TAllowAllAccessPolicy.Create, FProviders, FClock);
  FAuthorizationServer := TAuthorizationServer.Create(FStores, FRegistry, FProviders, FAccounts, FTokens, FAuthSettings, FClock);
  FSessions := TWebSessions.Create(FStores.Sessions, FTokens, FAuthSettings, FClock);
  FPages := TWebStencilsPageRenderer.Create(FAuthSettings.ProjectTemplatesPath, FAuthSettings.LibraryTemplatesPath);
end;

procedure TServerComposition.BuildRouters;
begin
  FOAuthController := TOAuthController.Create(FAuthorizationServer, FStores.Clients, FSessions, FPages, FTokens, FAuthSettings, FClock);
  FAccountController := TAccountController.Create(FAuthorizationServer, FAccounts, FRegistry, FProviders, FSessions, FPages, FStores, FAuthSettings);
  FInternalController := TInternalController.Create(FRegistry, FStores.Tokens, FAccounts);

  FPublicRouter := TWebRouter.Create;
  FOAuthController.Register(FPublicRouter);
  FAccountController.Register(FPublicRouter);

  FInternalRouter := TWebRouter.Create;
  FInternalController.Register(FInternalRouter);
end;

procedure TServerComposition.StartListeners;
begin
  FInternalHost := CreateHost(FInternalRouter, FSettings.InternalPort, FSettings.InternalBind);
  FPublicHost := CreateHost(FPublicRouter, FSettings.PublicPort, FSettings.PublicBind);

  FInternalHost.Start;
  FPublicHost.Start;
end;

function TServerComposition.CreateHost(const Router: TWebRouter; const Port: Word; const BindAddress: string): TMCPAuthWebServer;
begin
  Result := TMCPAuthWebServer.Create(Router, Port, BindAddress);
  Result.MaxConnections := TMCPAuthWebServer.DEFAULT_MAX_CONNECTIONS;
  Result.ReadTimeoutMs := TMCPAuthWebServer.DEFAULT_READ_TIMEOUT_MS;
end;

procedure TServerComposition.LogStarted;
begin
  const UsesPostgres = (FSettings.Store = TServerStoreKind.Postgres);
  const StoreName = IfThen(UsesPostgres, PostgresDialect, 'memory');

  TLogger.Info(StartedFormat, [FSettings.Issuer, FSettings.PublicBind, PublicPort, FSettings.InternalBind, InternalPort, StoreName]);
end;

procedure TServerComposition.Restart;
begin
  FInternalHost.Start;
  FPublicHost.Start;
  FMaintenance.Start;
  FIsRunning := True;
  LogStarted;
end;

procedure TServerComposition.Stop;
begin
  if Assigned(FMaintenance) then
    FMaintenance.Stop;
  if Assigned(FPublicHost) then
    FPublicHost.Stop;
  if Assigned(FInternalHost) then
    FInternalHost.Stop;

  FIsRunning := False;
end;

function TServerComposition.IsRunning: Boolean;
begin
  Result := FIsRunning;
end;

function TServerComposition.PublicPort: Word;
begin
  if Assigned(FPublicHost) then
    Result := FPublicHost.BoundPort
  else
    Result := FSettings.PublicPort;
end;

function TServerComposition.InternalPort: Word;
begin
  if Assigned(FInternalHost) then
    Result := FInternalHost.BoundPort
  else
    Result := FSettings.InternalPort;
end;

end.
