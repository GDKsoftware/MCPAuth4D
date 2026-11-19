unit MCPAuth.Identity.Access.Interfaces;

interface

uses
  MCPAuth.Upstream.Types;

type
  // Decides whether an upstream identity may sign in or be linked at all.
  IAccessPolicy = interface
    ['{6C2F8E14-A93B-4D57-B0E6-1F7A3D9C5B28}']
    function IsAllowed(const Identity: TUpstreamIdentity): Boolean;
  end;

implementation

end.
