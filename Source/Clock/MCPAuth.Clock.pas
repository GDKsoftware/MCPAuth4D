unit MCPAuth.Clock;

interface

uses
  MCPAuth.Clock.Interfaces;

type
  TSystemClock = class(TInterfacedObject, IClock)
  public
    function NowUtc: TDateTime;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils;

{ TSystemClock }

function TSystemClock.NowUtc: TDateTime;
begin
  Result := TTimeZone.Local.ToUniversalTime(Now);
end;

end.
