unit MCPAuth.Resource.Registry.Json;

interface

uses
  System.JSON,
  Spring.Collections,
  MCPAuth.Resource.Types,
  MCPAuth.Resource.Interfaces;

type
  TJsonResourceRegistry = class(TInterfacedObject, IResourceRegistry)
  private
    FResources: TArray<TResourceDefinition>;
    FByUri: IDictionary<string, TResourceDefinition>;
    FByServiceId: IDictionary<string, TResourceDefinition>;

    constructor Create(const Resources: TArray<TResourceDefinition>);

    class function ParseResources(const Root: TJSONValue; const AllowHttpResources: Boolean): TArray<TResourceDefinition>; static;
    class function ParseResource(const Entry: TJSONValue; const Context: string; const AllowHttpResources: Boolean): TResourceDefinition; static;
    class function ParseProviders(const Entry: TJSONObject; const Context: string): TArray<TResourceProvider>; static;
    class function ParseProvider(const Entry: TJSONValue; const Context: string): TResourceProvider; static;
    class function ParseScopes(const Entry: TJSONObject; const Context: string): TArray<string>; static;
    class function GetRequiredString(const Source: TJSONObject; const Name, Context: string): string; static;
    class function GetRequiredArray(const Source: TJSONObject; const Name, Context: string): TJSONArray; static;
    class procedure GuardResourceUri(const ResourceUri, Context: string; const AllowHttpResources: Boolean); static;
    class procedure GuardUnique(const Resources: TArray<TResourceDefinition>); static;

  public
    class function FromFile(const Path: string; const AllowHttpResources: Boolean = False): IResourceRegistry; static;
    class function FromJson(const Json: string; const AllowHttpResources: Boolean = False): IResourceRegistry; static;

    function TryGetByUri(const ResourceUri: string; out Resource: TResourceDefinition): Boolean;
    function TryGetByServiceId(const ServiceId: string; out Resource: TResourceDefinition): Boolean;
    function All: TArray<TResourceDefinition>;
    function ScopesForProvider(const Provider: string): TArray<string>;
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  System.Generics.Collections,
  MCPAuth.Resource.Exceptions;

const
  ResourcesField = 'resources';
  ResourceField = 'resource';
  NameField = 'name';
  ServiceIdField = 'service_id';
  SecretHashField = 'service_secret_sha256';
  ProvidersField = 'providers';
  ProviderField = 'provider';
  ScopesField = 'scopes';

  HttpsPrefix = 'https://';
  HttpPrefix = 'http://';

{ TJsonResourceRegistry }

class function TJsonResourceRegistry.FromFile(const Path: string; const AllowHttpResources: Boolean): IResourceRegistry;
begin
  const FileFound = TFile.Exists(Path);
  if not FileFound then
    raise EResourceRegistryInvalid.CreateFmt('Resource registry file "%s" does not exist', [Path]);

  var Json: string;
  try
    Json := TFile.ReadAllText(Path, TEncoding.UTF8);
  except
    on E: EInOutError do
      raise EResourceRegistryInvalid.CreateFmt('Resource registry file "%s" cannot be read: %s', [Path, E.Message]);
  end;

  Result := FromJson(Json, AllowHttpResources);
end;

class function TJsonResourceRegistry.FromJson(const Json: string; const AllowHttpResources: Boolean): IResourceRegistry;
begin
  const Root = TJSONObject.ParseJSONValue(Json);
  if not Assigned(Root) then
    raise EResourceRegistryInvalid.Create('Resource registry is not valid JSON');

  try
    const Resources = ParseResources(Root, AllowHttpResources);
    GuardUnique(Resources);
    Result := TJsonResourceRegistry.Create(Resources);
  finally
    Root.Free;
  end;
end;

constructor TJsonResourceRegistry.Create(const Resources: TArray<TResourceDefinition>);
begin
  inherited Create;

  FResources := Resources;
  FByUri := TCollections.CreateDictionary<string, TResourceDefinition>;
  FByServiceId := TCollections.CreateDictionary<string, TResourceDefinition>;

  for var Resource in Resources do
  begin
    FByUri.Add(Resource.ResourceUri, Resource);
    FByServiceId.Add(Resource.ServiceId, Resource);
  end;
end;

class function TJsonResourceRegistry.ParseResources(const Root: TJSONValue; const AllowHttpResources: Boolean): TArray<TResourceDefinition>;
begin
  const RootIsObject = (Root is TJSONObject);
  if not RootIsObject then
    raise EResourceRegistryInvalid.Create('Resource registry must be a JSON object');

  const Entries = GetRequiredArray(TJSONObject(Root), ResourcesField, 'registry');

  SetLength(Result, Entries.Count);
  for var Index := 0 to Entries.Count - 1 do
  begin
    const Context = Format('resources[%d]', [Index]);
    Result[Index] := ParseResource(Entries.Items[Index], Context, AllowHttpResources);
  end;
end;

class function TJsonResourceRegistry.ParseResource(const Entry: TJSONValue; const Context: string; const AllowHttpResources: Boolean): TResourceDefinition;
begin
  const EntryIsObject = (Entry is TJSONObject);
  if not EntryIsObject then
    raise EResourceRegistryInvalid.CreateFmt('%s must be a JSON object', [Context]);

  const Source = TJSONObject(Entry);
  Result.ResourceUri := GetRequiredString(Source, ResourceField, Context);
  Result.DisplayName := GetRequiredString(Source, NameField, Context);
  Result.ServiceId := GetRequiredString(Source, ServiceIdField, Context);
  Result.ServiceSecretHash := GetRequiredString(Source, SecretHashField, Context);
  GuardResourceUri(Result.ResourceUri, Context, AllowHttpResources);
  Result.Providers := ParseProviders(Source, Context);
end;

class function TJsonResourceRegistry.ParseProviders(const Entry: TJSONObject; const Context: string): TArray<TResourceProvider>;
begin
  const Entries = GetRequiredArray(Entry, ProvidersField, Context);

  SetLength(Result, Entries.Count);
  for var Index := 0 to Entries.Count - 1 do
  begin
    const ProviderContext = Format('%s.providers[%d]', [Context, Index]);
    Result[Index] := ParseProvider(Entries.Items[Index], ProviderContext);

    for var Previous := 0 to Index - 1 do
    begin
      const IsDuplicate = (Result[Previous].Provider = Result[Index].Provider);
      if IsDuplicate then
        raise EResourceRegistryInvalid.CreateFmt('%s repeats a provider', [ProviderContext]);
    end;
  end;
end;

class function TJsonResourceRegistry.ParseProvider(const Entry: TJSONValue; const Context: string): TResourceProvider;
begin
  const EntryIsObject = (Entry is TJSONObject);
  if not EntryIsObject then
    raise EResourceRegistryInvalid.CreateFmt('%s must be a JSON object', [Context]);

  const Source = TJSONObject(Entry);
  Result.Provider := GetRequiredString(Source, ProviderField, Context);
  Result.Scopes := ParseScopes(Source, Context);
end;

class function TJsonResourceRegistry.ParseScopes(const Entry: TJSONObject; const Context: string): TArray<string>;
begin
  const Entries = GetRequiredArray(Entry, ScopesField, Context);

  SetLength(Result, Entries.Count);
  for var Index := 0 to Entries.Count - 1 do
  begin
    const Scope = Entries.Items[Index];
    const IsText = (Scope is TJSONString);
    if not IsText then
      raise EResourceRegistryInvalid.CreateFmt('%s.scopes[%d] must be a string', [Context, Index]);

    Result[Index] := Scope.Value;
  end;
end;

class function TJsonResourceRegistry.GetRequiredString(const Source: TJSONObject; const Name, Context: string): string;
begin
  var Value: TJSONValue;
  const HasValue = Source.TryGetValue<TJSONValue>(Name, Value);
  const IsText = (HasValue and (Value is TJSONString));
  if not IsText then
    raise EResourceRegistryInvalid.CreateFmt('%s: field "%s" is missing or not a string', [Context, Name]);

  Result := Value.Value;
  if Result.Trim.IsEmpty then
    raise EResourceRegistryInvalid.CreateFmt('%s: field "%s" is empty', [Context, Name]);
end;

class function TJsonResourceRegistry.GetRequiredArray(const Source: TJSONObject; const Name, Context: string): TJSONArray;
begin
  var Value: TJSONValue;
  const HasValue = Source.TryGetValue<TJSONValue>(Name, Value);
  const IsArray = (HasValue and (Value is TJSONArray));
  if not IsArray then
    raise EResourceRegistryInvalid.CreateFmt('%s: field "%s" is missing or not an array', [Context, Name]);

  Result := TJSONArray(Value);
end;

class procedure TJsonResourceRegistry.GuardResourceUri(const ResourceUri, Context: string; const AllowHttpResources: Boolean);
begin
  const IsHttps = ResourceUri.StartsWith(HttpsPrefix, True);
  const IsHttp = ResourceUri.StartsWith(HttpPrefix, True);
  const IsAllowed = (IsHttps or (IsHttp and AllowHttpResources));
  if not IsAllowed then
    raise EResourceRegistryInvalid.CreateFmt('%s: field "%s" must be an https URL', [Context, ResourceField]);
end;

class procedure TJsonResourceRegistry.GuardUnique(const Resources: TArray<TResourceDefinition>);
begin
  for var Index := 0 to High(Resources) do
  begin
    for var Previous := 0 to Index - 1 do
    begin
      if Resources[Previous].ResourceUri = Resources[Index].ResourceUri then
        raise EResourceRegistryInvalid.CreateFmt('resources[%d]: field "%s" duplicates resources[%d]', [Index, ResourceField, Previous]);

      if Resources[Previous].ServiceId = Resources[Index].ServiceId then
        raise EResourceRegistryInvalid.CreateFmt('resources[%d]: field "%s" duplicates resources[%d]', [Index, ServiceIdField, Previous]);
    end;
  end;
end;

function TJsonResourceRegistry.TryGetByUri(const ResourceUri: string; out Resource: TResourceDefinition): Boolean;
begin
  Result := FByUri.TryGetValue(ResourceUri, Resource);
  if not Result then
    Resource := Default(TResourceDefinition);
end;

function TJsonResourceRegistry.TryGetByServiceId(const ServiceId: string; out Resource: TResourceDefinition): Boolean;
begin
  Result := FByServiceId.TryGetValue(ServiceId, Resource);
  if not Result then
    Resource := Default(TResourceDefinition);
end;

function TJsonResourceRegistry.All: TArray<TResourceDefinition>;
begin
  Result := Copy(FResources);
end;

function TJsonResourceRegistry.ScopesForProvider(const Provider: string): TArray<string>;
begin
  const Scopes = TCollections.CreateSet<string>;
  for var Resource in FResources do
  begin
    for var ResourceProvider in Resource.Providers do
    begin
      const IsRequestedProvider = (ResourceProvider.Provider = Provider);
      if IsRequestedProvider then
        Scopes.AddRange(ResourceProvider.Scopes);
    end;
  end;

  Result := Scopes.ToArray;
  TArray.Sort<string>(Result);
end;

end.
