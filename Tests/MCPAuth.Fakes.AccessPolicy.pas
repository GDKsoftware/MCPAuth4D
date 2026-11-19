unit MCPAuth.Fakes.AccessPolicy;

interface

uses
  MCPAuth.Upstream.Types,
  MCPAuth.Identity.Access.Interfaces;

type
  TFakeAccessPolicy = class(TInterfacedObject, IAccessPolicy)
  private
    FIsAllowing: Boolean;

  public
    constructor Create;

    function IsAllowed(const Identity: TUpstreamIdentity): Boolean;

    property IsAllowing: Boolean read FIsAllowing write FIsAllowing;
  end;

implementation

{ TFakeAccessPolicy }

constructor TFakeAccessPolicy.Create;
begin
  inherited Create;

  FIsAllowing := True;
end;

function TFakeAccessPolicy.IsAllowed(const Identity: TUpstreamIdentity): Boolean;
begin
  Result := FIsAllowing;
end;

end.
