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

  public
    // Raises EArgumentException when two providers share a name.
    constructor Create(const Providers: TArray<IUpstreamProvider>);

    function TryGet(const Name: string; out Provider: IUpstreamProvider): Boolean;
    function Names: TArray<string>;
  end;

implementation

uses
  System.SysUtils;

{ TUpstreamProviders }

class function TUpstreamProviders.KeyOf(const Name: string): string;
begin
  Result := Name.ToLowerInvariant;
end;

constructor TUpstreamProviders.Create(const Providers: TArray<IUpstreamProvider>);
begin
  inherited Create;

  FProviders := TCollections.CreateDictionary<string, IUpstreamProvider>;
  for var Provider in Providers do
  begin
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
