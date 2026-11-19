unit MCPAuth.Upstream.Exceptions;

interface

uses
  System.SysUtils;

type
  EUpstreamError = class(Exception);
  EUpstreamGrantRevoked = class(EUpstreamError);
  EUpstreamTokenMalformed = class(EUpstreamError);
  EUpstreamCredentialInvalid = class(EUpstreamError);

implementation

end.
