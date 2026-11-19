unit MCPAuth.Server.Maintenance;

interface

uses
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  MCPAuth.Clock.Interfaces,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.Store.Interfaces;

type
  // Deletes expired tokens and sessions on a background thread, once per interval.
  // Stop wakes the thread, so it ends within the time of one running cleanup.
  TServerMaintenance = class
  private
    FTokens: ITokenRepository;
    FSessions: ISessionStore;
    FClock: IClock;
    FIntervalMs: Cardinal;
    FStopEvent: TEvent;
    FThread: TThread;
    FRunCount: Integer;

    procedure RunUntilStopped;
    procedure RunGuarded;

  public
    const DEFAULT_INTERVAL_MS = 60 * 60 * 1000;

    constructor Create(const Tokens: ITokenRepository; const Sessions: ISessionStore; const Clock: IClock; const IntervalMs: Cardinal = DEFAULT_INTERVAL_MS);
    destructor Destroy; override;

    procedure Start;
    procedure Stop;
    procedure RunOnce;
    function RunCount: Integer;
  end;

implementation

uses
  MCPServer.Logger;

const
  CleanupFailedFormat = 'Maintenance failed with %s';
  CleanupDoneFormat = 'Maintenance deleted %d expired tokens and %d expired sessions';

{ TServerMaintenance }

constructor TServerMaintenance.Create(const Tokens: ITokenRepository; const Sessions: ISessionStore; const Clock: IClock; const IntervalMs: Cardinal);
begin
  inherited Create;

  FTokens := Tokens;
  FSessions := Sessions;
  FClock := Clock;
  FIntervalMs := IntervalMs;
  FStopEvent := TEvent.Create(nil, True, False, '');
end;

destructor TServerMaintenance.Destroy;
begin
  Stop;
  FStopEvent.Free;
  inherited Destroy;
end;

procedure TServerMaintenance.Start;
begin
  if Assigned(FThread) then
    Exit;

  FStopEvent.ResetEvent;
  FThread := TThread.CreateAnonymousThread(RunUntilStopped);
  FThread.FreeOnTerminate := False;
  FThread.Start;
end;

procedure TServerMaintenance.Stop;
begin
  if not Assigned(FThread) then
    Exit;

  FStopEvent.SetEvent;
  FThread.WaitFor;
  FreeAndNil(FThread);
end;

procedure TServerMaintenance.RunUntilStopped;
begin
  while FStopEvent.WaitFor(FIntervalMs) = TWaitResult.wrTimeout do
  begin
    RunGuarded;
  end;
end;

procedure TServerMaintenance.RunGuarded;
begin
  // A failing cleanup (for example a database that is briefly unreachable) must not end the thread;
  // the next interval tries again.
  try
    RunOnce;
  except
    on E: Exception do
      TLogger.Error(CleanupFailedFormat, [E.ClassName]);
  end;
end;

procedure TServerMaintenance.RunOnce;
begin
  const NowUtc = FClock.NowUtc;

  const DeletedTokens = FTokens.DeleteExpired(NowUtc);
  const DeletedSessions = FSessions.DeleteExpired(NowUtc);

  TInterlocked.Increment(FRunCount);
  TLogger.Info(CleanupDoneFormat, [DeletedTokens, DeletedSessions]);
end;

function TServerMaintenance.RunCount: Integer;
begin
  Result := TInterlocked.CompareExchange(FRunCount, 0, 0);
end;

end.
