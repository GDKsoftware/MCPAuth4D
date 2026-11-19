unit MCPAuth.Store.Memory.Clients;

interface

uses
  System.SyncObjs,
  Spring.Collections,
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces;

type
  TMemoryClientRepository = class(TInterfacedObject, IClientRepository)
  private
    FLock: TCriticalSection;
    FClients: IDictionary<string, TOAuthClient>;

  public
    constructor Create;
    destructor Destroy; override;

    function TryGet(const ClientId: string; out Client: TOAuthClient): Boolean;
    procedure Save(const Client: TOAuthClient);
  end;

implementation

{ TMemoryClientRepository }

constructor TMemoryClientRepository.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FClients := TCollections.CreateDictionary<string, TOAuthClient>;
end;

destructor TMemoryClientRepository.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TMemoryClientRepository.TryGet(const ClientId: string; out Client: TOAuthClient): Boolean;
begin
  FLock.Enter;
  try
    Result := FClients.TryGetValue(ClientId, Client);
  finally
    FLock.Leave;
  end;
end;

procedure TMemoryClientRepository.Save(const Client: TOAuthClient);
begin
  FLock.Enter;
  try
    FClients[Client.ClientId] := Client;
  finally
    FLock.Leave;
  end;
end;

end.
