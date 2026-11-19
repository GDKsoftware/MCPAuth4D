unit MCPAuth.Store.FireDAC.Clients;

interface

uses
  MCPAuth.OAuth.Types,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.Store.FireDAC.Interfaces,
  MCPAuth.Store.FireDAC.Dialect;

type
  // Redirect URIs share one column, separated by line feeds; a valid URI never contains one.
  TFireDACClientRepository = class(TInterfacedObject, IClientRepository)
  private
    FFactory: IFireDACConnectionFactory;
    FDialect: TSqlDialect;

  public
    constructor Create(const Factory: IFireDACConnectionFactory; const Dialect: TSqlDialect);

    function TryGet(const ClientId: string; out Client: TOAuthClient): Boolean;
    procedure Save(const Client: TOAuthClient);
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Store.FireDAC.Command;

const
  UriSeparator = #10;
  SelectClient = 'SELECT client_id, client_name, redirect_uris, created_at FROM mcpauth_clients WHERE client_id = :client_id';

{ TFireDACClientRepository }

constructor TFireDACClientRepository.Create(const Factory: IFireDACConnectionFactory; const Dialect: TSqlDialect);
begin
  inherited Create;
  FFactory := Factory;
  FDialect := Dialect;
end;

function TFireDACClientRepository.TryGet(const ClientId: string; out Client: TOAuthClient): Boolean;
begin
  Client := Default(TOAuthClient);

  const Command = TFireDACCommand.Create(FFactory, SelectClient);
  try
    Command.SetText('client_id', ClientId);
    Command.Open;

    Result := not Command.Eof;
    if Result then
    begin
      Client.ClientId := Command.Text('client_id');
      Client.ClientName := Command.Text('client_name');
      Client.RedirectUris := Command.Text('redirect_uris').Split([UriSeparator], TStringSplitOptions.ExcludeEmpty);
      Client.CreatedAtUtc := Command.Utc('created_at');
    end;
  finally
    Command.Free;
  end;
end;

procedure TFireDACClientRepository.Save(const Client: TOAuthClient);
begin
  const Sql = FDialect.Upsert('mcpauth_clients', 'client_id', ['client_id', 'client_name', 'redirect_uris', 'created_at']);
  const Command = TFireDACCommand.Create(FFactory, Sql);
  try
    Command.SetText('client_id', Client.ClientId);
    Command.SetText('client_name', Client.ClientName);
    Command.SetLongText('redirect_uris', string.Join(UriSeparator, Client.RedirectUris));
    Command.SetUtc('created_at', Client.CreatedAtUtc);
    Command.Execute;
  finally
    Command.Free;
  end;
end;

end.
