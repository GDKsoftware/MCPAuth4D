unit MCPAuth.Clock.Interfaces;

interface

type
  IClock = interface
    ['{5B1D6C0A-3F52-4E8B-9D47-0C6A1E7F2B93}']
    function NowUtc: TDateTime;
  end;

implementation

end.
