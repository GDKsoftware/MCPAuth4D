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
  // Read from the UTC clock of the OS: converting local time is ambiguous in the hour a DST change repeats.
  Result := TDateTime.NowUTC;
end;

end.
