unit MCPAuth.Upstream.Interfaces;

interface

uses
  Spring.Collections,
  MCPAuth.Upstream.Types;

type
  IUpstreamProvider = interface
    ['{4E0C2B7A-91D3-4F6E-A8B5-3C7D1E9F2A64}']
    function AuthorizationUrl(const State, CodeChallenge, RedirectUri: string): string;
    function ExchangeCode(const Code, CodeVerifier, RedirectUri: string): TUpstreamTokens;
    function Refresh(const RefreshToken: string): TUpstreamTokens;

    function GetName: string;
    property Name: string read GetName;
  end;

  IUpstreamProviders = interface
    ['{B83F5D21-6A4C-4E97-9D02-7F1A3C5E8B46}']
    function TryGet(const Name: string; out Provider: IUpstreamProvider): Boolean;
    function Names: TArray<string>;
  end;

  IClientCredential = interface
    ['{D2A9E64F-3B18-4C75-B0E3-5F8C2A71D903}']
    function WithCredential(const TokenUrl: string; const Fields: TArray<TPair<string, string>>): TArray<TPair<string, string>>;
  end;

implementation

end.
