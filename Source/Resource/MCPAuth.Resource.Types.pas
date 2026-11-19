unit MCPAuth.Resource.Types;

interface

type
  TResourceProvider = record
    Provider: string;
    Scopes: TArray<string>;
  end;

  TResourceDefinition = record
    ResourceUri: string;
    DisplayName: string;
    ServiceId: string;
    ServiceSecretHash: string;
    Providers: TArray<TResourceProvider>;
  end;

implementation

end.
