unit MCPAuth.Upstream.Providers;

interface

uses
  Spring.Collections,
  MCPAuth.Upstream.Interfaces;

type
  // Provider names are matched case-insensitively; they also form the callback path.
  TUpstreamProviders = class(TInterfacedObject, IUpstreamProviders)
  private
    FProviders: IDictionary<string, IUpstreamProvider>;
    FNames: TArray<string>;

    class function KeyOf(const Name: string): string; static;
    class procedure GuardName(const Name: string); static;

  public
    // Raises EArgumentException when two providers share a name, or when a name contains ':', the separator of account keys.
    constructor Create(const Providers: TArray<IUpstreamProvider>);

    function TryGet(const Name: string; out Provider: IUpstreamProvider): Boolean;
    function Names: TArray<string>;
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Identity.Types;

{ TUpstreamProviders }

class function TUpstreamProviders.KeyOf(const Name: string): string;
begin
  Result := Name.ToLowerInvariant;
end;

class procedure TUpstreamProviders.GuardName(const Name: string);
begin
  if Name.Contains(AccountKeySeparator) then
    raise EArgumentException.CreateFmt('Upstream provider name "%s" contains "%s"', [Name, AccountKeySeparator]);
end;

constructor TUpstreamProviders.Create(const Providers: TArray<IUpstreamProvider>);
begin
  inherited Create;

  FProviders := TCollections.CreateDictionary<string, IUpstreamProvider>;
  for var Provider in Providers do
  begin
    GuardName(Provider.Name);

    const Key = KeyOf(Provider.Name);
    if FProviders.ContainsKey(Key) then
      raise EArgumentException.CreateFmt('Upstream provider "%s" is registered twice', [Provider.Name]);

    FProviders.Add(Key, Provider);
    FNames := FNames + [Provider.Name];
  end;
end;

function TUpstreamProviders.TryGet(const Name: string; out Provider: IUpstreamProvider): Boolean;
begin
  Result := FProviders.TryGetValue(KeyOf(Name), Provider);
end;

function TUpstreamProviders.Names: TArray<string>;
begin
  Result := Copy(FNames);
end;

end.
