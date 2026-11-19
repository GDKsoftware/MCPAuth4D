program WhoAmIServer;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  MCPAuth.Server.Shutdown,
  WhoAmI.Tool.Params in 'WhoAmI.Tool.Params.pas',
  WhoAmI.Tool in 'WhoAmI.Tool.pas',
  WhoAmI.Server in 'WhoAmI.Server.pas';

begin
  TShutdownSignal.Prepare;
  System.ExitCode := TWhoAmIServer.Run;
end.
