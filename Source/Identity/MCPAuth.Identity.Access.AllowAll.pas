unit MCPAuth.Identity.Access.AllowAll;

interface

uses
  MCPAuth.Upstream.Types,
  MCPAuth.Identity.Access.Interfaces;

type
  TAllowAllAccessPolicy = class(TInterfacedObject, IAccessPolicy)
  public
    function IsAllowed(const Identity: TUpstreamIdentity): Boolean;
  end;

implementation

{ TAllowAllAccessPolicy }

function TAllowAllAccessPolicy.IsAllowed(const Identity: TUpstreamIdentity): Boolean;
begin
  Result := True;
end;

end.
