unit MCPAuth.Upstream.Credential.Secret;

interface

uses
  Spring.Collections,
  MCPAuth.Upstream.Interfaces;

type
  TClientSecretCredential = class(TInterfacedObject, IClientCredential)
  private
    FClientId: string;
    FSecret: string;

  public
    constructor Create(const ClientId, Secret: string);

    function WithCredential(const TokenUrl: string; const Fields: TArray<TPair<string, string>>): TArray<TPair<string, string>>;
  end;

implementation

{ TClientSecretCredential }

constructor TClientSecretCredential.Create(const ClientId, Secret: string);
begin
  inherited Create;
  FClientId := ClientId;
  FSecret   := Secret;
end;

function TClientSecretCredential.WithCredential(const TokenUrl: string; const Fields: TArray<TPair<string, string>>): TArray<TPair<string, string>>;
begin
  const ClientIdField = TPair<string, string>.Create('client_id', FClientId);
  const SecretField = TPair<string, string>.Create('client_secret', FSecret);

  Result := Fields + [ClientIdField, SecretField];
end;

end.
