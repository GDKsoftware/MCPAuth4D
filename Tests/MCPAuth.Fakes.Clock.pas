unit MCPAuth.Fakes.Clock;

interface

uses
  MCPAuth.Clock.Interfaces;

type
  TFakeClock = class(TInterfacedObject, IClock)
  private
    FNowUtc: TDateTime;

  public
    constructor Create(const NowUtc: TDateTime);

    function NowUtc: TDateTime;

    procedure SetNowUtc(const Value: TDateTime);
    procedure AdvanceSeconds(const Seconds: Integer);
  end;

implementation

uses
  System.DateUtils;

{ TFakeClock }

constructor TFakeClock.Create(const NowUtc: TDateTime);
begin
  inherited Create;
  FNowUtc := NowUtc;
end;

function TFakeClock.NowUtc: TDateTime;
begin
  Result := FNowUtc;
end;

procedure TFakeClock.SetNowUtc(const Value: TDateTime);
begin
  FNowUtc := Value;
end;

procedure TFakeClock.AdvanceSeconds(const Seconds: Integer);
begin
  FNowUtc := IncSecond(FNowUtc, Seconds);
end;

end.
