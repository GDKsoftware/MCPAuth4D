unit MCPAuth.Server.Shutdown;

interface

uses
  System.SysUtils,
  System.SyncObjs
  {$IFDEF MSWINDOWS}
  , Winapi.Windows
  {$ENDIF}
  {$IFDEF POSIX}
  , Posix.Signal
  {$ENDIF}
  ;

type
  // Waits for Ctrl+C or a console close on Windows and for SIGINT or SIGTERM on Linux (systemd stop),
  // so a console program can stop its listeners before it exits.
  TShutdownSignal = class
  private
    {$IFDEF MSWINDOWS}
    class var FSignalled: TEvent;
    class function HandleConsoleControl(ControlType: DWORD): BOOL; stdcall; static;
    {$ENDIF}
    {$IFDEF POSIX}
    class function StopSignals: sigset_t; static;
    {$ENDIF}

  public
    // Call first thing in the program, before any thread starts: on Linux every later thread inherits
    // the blocked signals, so only WaitForSignal receives them.
    class procedure Prepare; static;
    class procedure WaitForSignal; static;
  end;

implementation

{ TShutdownSignal }

{$IFDEF MSWINDOWS}

class function TShutdownSignal.HandleConsoleControl(ControlType: DWORD): BOOL;
begin
  FSignalled.SetEvent;
  Result := True;
end;

class procedure TShutdownSignal.Prepare;
begin
  if not Assigned(FSignalled) then
    FSignalled := TEvent.Create(nil, True, False, '');

  SetConsoleCtrlHandler(@HandleConsoleControl, True);
end;

class procedure TShutdownSignal.WaitForSignal;
begin
  try
    FSignalled.WaitFor(INFINITE);
  finally
    SetConsoleCtrlHandler(@HandleConsoleControl, False);
    FreeAndNil(FSignalled);
  end;
end;

{$ENDIF}

{$IFDEF POSIX}

class function TShutdownSignal.StopSignals: sigset_t;
begin
  sigemptyset(Result);
  sigaddset(Result, SIGINT);
  sigaddset(Result, SIGTERM);
end;

class procedure TShutdownSignal.Prepare;
begin
  var Signals := StopSignals;
  pthread_sigmask(SIG_BLOCK, @Signals, nil);
end;

class procedure TShutdownSignal.WaitForSignal;
begin
  var Signals := StopSignals;
  var ReceivedSignal: Integer;
  sigwait(Signals, @ReceivedSignal);
end;

{$ENDIF}

end.
