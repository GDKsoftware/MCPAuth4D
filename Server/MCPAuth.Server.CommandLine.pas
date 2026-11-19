unit MCPAuth.Server.CommandLine;

interface

type
  // The command line of MCPAuthServer:
  //   MCPAuthServer                        runs the server with the settings from the environment
  //   MCPAuthServer --hash-secret [secret] prints the registry hash of a service secret (read from stdin
  //                                        when it is not given, so it stays out of the shell history)
  TServerCommandLine = class
  private
    class function IsHashSecretCommand: Boolean; static;
    class function PrintSecretHash: Integer; static;
    class function ReadSecret: string; static;
    class function RunServer: Integer; static;
    class procedure ServeUntilSignal; static;

  public
    class function Run: Integer; static;
  end;

implementation

uses
  System.SysUtils,
  MCPServer.Logger,
  MCPAuth.Resource.ServiceAuth,
  MCPAuth.Server.Settings,
  MCPAuth.Server.Composition,
  MCPAuth.Server.Shutdown;

const
  HashSecretSwitch = '--hash-secret';
  ExitSuccess = 0;
  ExitStartupFailed = 1;
  ExitUsage = 2;

resourcestring
  EmptySecret = 'No secret given; pass it after --hash-secret or on standard input';
  StartupFailedFormat = 'Startup failed: %s: %s';
  StoppingMessage = 'Stop signal received, stopping';

{ TServerCommandLine }

class function TServerCommandLine.Run: Integer;
begin
  if IsHashSecretCommand then
    Result := PrintSecretHash
  else
    Result := RunServer;
end;

class function TServerCommandLine.IsHashSecretCommand: Boolean;
begin
  Result := ((ParamCount >= 1) and SameText(ParamStr(1), HashSecretSwitch));
end;

class function TServerCommandLine.PrintSecretHash: Integer;
begin
  const Secret = ReadSecret;
  if Secret.IsEmpty then
  begin
    Writeln(ErrOutput, EmptySecret);
    Exit(ExitUsage);
  end;

  Writeln(TServiceAuthenticator.HashSecret(Secret));
  Result := ExitSuccess;
end;

class function TServerCommandLine.ReadSecret: string;
begin
  const HasSecretArgument = (ParamCount >= 2);
  if HasSecretArgument then
    Exit(ParamStr(2));

  var Line: string;
  Readln(Line);
  Result := Line.Trim;
end;

class function TServerCommandLine.RunServer: Integer;
begin
  TLogger.LogToConsole := True;

  try
    ServeUntilSignal;
    Result := ExitSuccess;
  except
    // Startup errors name settings, files and resources; none of the configuration errors carries a value.
    on E: Exception do
    begin
      TLogger.Error(StartupFailedFormat, [E.ClassName, E.Message]);
      Result := ExitStartupFailed;
    end;
  end;
end;

class procedure TServerCommandLine.ServeUntilSignal;
begin
  const Settings = TServerSettings.FromEnvironment;
  const Composition = TServerComposition.Create(Settings);
  try
    Composition.Start;
    TShutdownSignal.WaitForSignal;

    TLogger.Info(StoppingMessage);
    Composition.Stop;
  finally
    Composition.Free;
  end;
end;

end.
