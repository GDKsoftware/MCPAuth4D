unit MCPAuth.Upstream.Types;

interface

uses
  Spring.Collections,
  MCPAuth.Identity.Types;

type
  TUpstreamIdentity = record
    Key: TAccountKey;
    DisplayName: string;
    UserName: string;
  end;

  TUpstreamTokens = record
    AccessToken: string;
    RefreshToken: string;
    Scope: string;
    ExpiresAtUtc: TDateTime;
    Identity: TUpstreamIdentity;
  end;

  TUpstreamAccessToken = record
    AccessToken: string;
    ExpiresAtUtc: TDateTime;
  end;

  TOAuthUpstreamSettings = record
    Name: string;
    AuthorizeUrl: string;
    TokenUrl: string;
    ClientId: string;
    Scopes: TArray<string>;
    ExtraAuthorizeParameters: TArray<TPair<string, string>>;
  end;

implementation

end.
