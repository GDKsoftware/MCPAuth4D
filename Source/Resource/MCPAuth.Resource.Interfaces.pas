unit MCPAuth.Resource.Interfaces;

interface

uses
  MCPAuth.Resource.Types;

type
  IResourceRegistry = interface
    ['{7A92D5E4-1C68-4B3F-8E07-F4A6B9C0D251}']
    function TryGetByUri(const ResourceUri: string; out Resource: TResourceDefinition): Boolean;
    function TryGetByServiceId(const ServiceId: string; out Resource: TResourceDefinition): Boolean;
    function All: TArray<TResourceDefinition>;

    // The union over all resources, sorted and without duplicates.
    function ScopesForProvider(const Provider: string): TArray<string>;
  end;

implementation

end.
