program MCPAuth.Tests;

{$APPTYPE CONSOLE}
{$STRONGLINKTYPES ON}

uses
  System.SysUtils,
  DUnitX.TestFramework,
  DUnitX.Loggers.Console,
  DUnitX.Loggers.XML.NUnit,
  MCPAuth.Secret.Token.Tests in 'MCPAuth.Secret.Token.Tests.pas',
  MCPAuth.Secret.Hash.Tests in 'MCPAuth.Secret.Hash.Tests.pas',
  MCPAuth.Secret.KeyRing.Tests in 'MCPAuth.Secret.KeyRing.Tests.pas',
  MCPAuth.Secret.AesGcm.Tests in 'MCPAuth.Secret.AesGcm.Tests.pas',
  MCPAuth.Fakes.Clock in 'MCPAuth.Fakes.Clock.pas',
  MCPAuth.Clock.Tests in 'MCPAuth.Clock.Tests.pas',
  MCPAuth.Identity.Types.Tests in 'MCPAuth.Identity.Types.Tests.pas',
  MCPAuth.Identity.Exceptions,
  MCPAuth.Identity.Interfaces,
  MCPAuth.Resource.Interfaces,
  MCPAuth.OAuth.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Store.Contract.Tests in 'MCPAuth.Store.Contract.Tests.pas',
  MCPAuth.Store.Memory.Tests in 'MCPAuth.Store.Memory.Tests.pas',
  MCPAuth.OAuth.Pkce.Tests in 'MCPAuth.OAuth.Pkce.Tests.pas',
  MCPAuth.OAuth.RedirectPolicy.Tests in 'MCPAuth.OAuth.RedirectPolicy.Tests.pas',
  MCPAuth.OAuth.Errors.Tests in 'MCPAuth.OAuth.Errors.Tests.pas';

begin
  ReportMemoryLeaksOnShutdown := True;
  try
    TDUnitX.CheckCommandLine;

    const Runner = TDUnitX.CreateRunner;
    Runner.UseRTTI := True;
    Runner.FailsOnNoAsserts := True;
    Runner.AddLogger(TDUnitXConsoleLogger.Create(True));

    const HasXmlOutput = not TDUnitX.Options.XMLOutputFile.IsEmpty;
    if HasXmlOutput then
      Runner.AddLogger(TDUnitXXMLNUnitFileLogger.Create(TDUnitX.Options.XMLOutputFile));

    const Results = Runner.Execute;
    if not Results.AllPassed then
      System.ExitCode := EXIT_ERRORS;
  except
    on E: Exception do
    begin
      Writeln(Format('%s: %s', [E.ClassName, E.Message]));
      System.ExitCode := EXIT_ERRORS;
    end;
  end;
end.
