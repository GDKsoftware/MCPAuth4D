program MCPAuthServer;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  MCPAuth.Server.Shutdown in 'MCPAuth.Server.Shutdown.pas',
  MCPAuth.Server.Exceptions in 'MCPAuth.Server.Exceptions.pas',
  MCPAuth.Server.Settings in 'MCPAuth.Server.Settings.pas',
  MCPAuth.Server.Maintenance in 'MCPAuth.Server.Maintenance.pas',
  MCPAuth.Server.Composition in 'MCPAuth.Server.Composition.pas',
  MCPAuth.Server.CommandLine in 'MCPAuth.Server.CommandLine.pas';

begin
  TShutdownSignal.Prepare;
  System.ExitCode := TServerCommandLine.Run;
end.
