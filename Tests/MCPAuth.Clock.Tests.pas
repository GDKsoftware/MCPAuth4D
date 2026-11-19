unit MCPAuth.Clock.Tests;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  TClockTests = class
  public
    [Test]
    procedure SystemClockReturnsCurrentUtcTime;

    [Test]
    procedure FakeClockAdvancesByGivenSeconds;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Clock,
  MCPAuth.Fakes.Clock;

{ TClockTests }

procedure TClockTests.SystemClockReturnsCurrentUtcTime;
begin
  const Clock: IClock = TSystemClock.Create;

  const Actual = Clock.NowUtc;

  const ExpectedUtc = TTimeZone.Local.ToUniversalTime(Now);
  Assert.IsTrue(SecondsBetween(ExpectedUtc, Actual) <= 2);
end;

procedure TClockTests.FakeClockAdvancesByGivenSeconds;
begin
  const Start = EncodeDateTime(2026, 1, 1, 12, 0, 0, 0);
  const FakeClock = TFakeClock.Create(Start);
  const Clock: IClock = FakeClock;

  FakeClock.AdvanceSeconds(90);

  Assert.AreEqual(IncSecond(Start, 90), Clock.NowUtc);
end;

end.
