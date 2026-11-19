unit MCPAuth.OAuth.Errors;

interface

uses
  System.SysUtils;

type
  TOAuthErrorCode = record
  public const
    InvalidRequest = 'invalid_request';
    InvalidClient = 'invalid_client';
    InvalidGrant = 'invalid_grant';
    UnauthorizedClient = 'unauthorized_client';
    UnsupportedGrantType = 'unsupported_grant_type';
    UnsupportedResponseType = 'unsupported_response_type';
    InvalidScope = 'invalid_scope';
    InvalidTarget = 'invalid_target';
    AccessDenied = 'access_denied';
    InvalidRedirectUri = 'invalid_redirect_uri';
    InvalidClientMetadata = 'invalid_client_metadata';
  end;

  EOAuthError = class(Exception)
  private
    FErrorCode: string;
    FStatusCode: Integer;

  public
    constructor Create(const ErrorCode, Description: string);

    property ErrorCode: string read FErrorCode;
    property StatusCode: Integer read FStatusCode;
  end;

implementation

const
  StatusBadRequest = 400;
  StatusUnauthorized = 401;

{ EOAuthError }

constructor EOAuthError.Create(const ErrorCode, Description: string);
begin
  inherited Create(Description);

  FErrorCode := ErrorCode;

  const IsClientAuthenticationFailure = (ErrorCode = TOAuthErrorCode.InvalidClient);
  if IsClientAuthenticationFailure then
    FStatusCode := StatusUnauthorized
  else
    FStatusCode := StatusBadRequest;
end;

end.
