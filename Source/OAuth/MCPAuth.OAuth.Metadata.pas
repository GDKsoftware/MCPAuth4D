unit MCPAuth.OAuth.Metadata;

interface

uses
  System.JSON,
  MCPAuth.OAuth.Settings;

type
  TAuthorizationServerMetadata = class
  private
    class function StringArray(const Values: array of string): TJSONArray; static;
  public
    // The caller owns the returned object.
    class function Build(const Settings: TMCPAuthSettings): TJSONObject; static;
  end;

implementation

uses
  System.SysUtils;

{ TAuthorizationServerMetadata }

class function TAuthorizationServerMetadata.Build(const Settings: TMCPAuthSettings): TJSONObject;
begin
  const Base = Settings.Issuer.TrimRight(['/']);

  Result := TJSONObject.Create;
  try
    Result.AddPair('issuer', Settings.Issuer);
    Result.AddPair('authorization_endpoint', Base + '/authorize');
    Result.AddPair('token_endpoint', Base + '/token');
    Result.AddPair('registration_endpoint', Base + '/register');
    Result.AddPair('revocation_endpoint', Base + '/revoke');
    Result.AddPair('response_types_supported', StringArray(['code']));
    Result.AddPair('grant_types_supported', StringArray(['authorization_code', 'refresh_token']));
    Result.AddPair('code_challenge_methods_supported', StringArray(['S256']));
    Result.AddPair('token_endpoint_auth_methods_supported', StringArray(['none']));
    Result.AddPair('scopes_supported', StringArray([Settings.Scope]));
  except
    Result.Free;
    raise;
  end;
end;

class function TAuthorizationServerMetadata.StringArray(const Values: array of string): TJSONArray;
begin
  Result := TJSONArray.Create;
  for var Value in Values do
    Result.Add(Value);
end;

end.
