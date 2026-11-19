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
  MCPAuth.OAuth.Errors.Tests in 'MCPAuth.OAuth.Errors.Tests.pas',
  MCPAuth.Resource.Registry.Json.Tests in 'MCPAuth.Resource.Registry.Json.Tests.pas',
  MCPAuth.Resource.ServiceAuth.Tests in 'MCPAuth.Resource.ServiceAuth.Tests.pas',
  MCPAuth.OAuth.Metadata.Tests in 'MCPAuth.OAuth.Metadata.Tests.pas',
  MCPAuth.OAuth.Registration.Tests in 'MCPAuth.OAuth.Registration.Tests.pas',
  MCPAuth.Fakes.UpstreamHttp in 'MCPAuth.Fakes.UpstreamHttp.pas',
  MCPAuth.Fakes.Jwt in 'MCPAuth.Fakes.Jwt.pas',
  MCPAuth.Fakes.SelfSignedCertificate in 'MCPAuth.Fakes.SelfSignedCertificate.pas',
  MCPAuth.Upstream.Jwt.Tests in 'MCPAuth.Upstream.Jwt.Tests.pas',
  MCPAuth.Upstream.FormEncoding.Tests in 'MCPAuth.Upstream.FormEncoding.Tests.pas',
  MCPAuth.Upstream.Credential.Secret.Tests in 'MCPAuth.Upstream.Credential.Secret.Tests.pas',
  MCPAuth.Upstream.Credential.Certificate.Tests in 'MCPAuth.Upstream.Credential.Certificate.Tests.pas',
  MCPAuth.Upstream.Microsoft.Tests in 'MCPAuth.Upstream.Microsoft.Tests.pas',
  MCPAuth.Fakes.UpstreamProvider in 'MCPAuth.Fakes.UpstreamProvider.pas',
  MCPAuth.Fakes.AccessPolicy in 'MCPAuth.Fakes.AccessPolicy.pas',
  MCPAuth.Upstream.Providers.Tests in 'MCPAuth.Upstream.Providers.Tests.pas',
  MCPAuth.Identity.Accounts.Tests in 'MCPAuth.Identity.Accounts.Tests.pas',
  MCPAuth.OAuth.Server.Tests in 'MCPAuth.OAuth.Server.Tests.pas',
  MCPAuth.Web.Page.WebStencils.Tests in 'MCPAuth.Web.Page.WebStencils.Tests.pas',
  MCPAuth.Web.Controller.OAuth.Tests in 'MCPAuth.Web.Controller.OAuth.Tests.pas',
  MCPAuth.Internal.Controller.Tests in 'MCPAuth.Internal.Controller.Tests.pas',
  MCPAuth.Web.Controller.Account.Tests in 'MCPAuth.Web.Controller.Account.Tests.pas',
  MCPAuth.Web.Server.Indy.Tests in 'MCPAuth.Web.Server.Indy.Tests.pas',
  MCPAuth.Client.Tests in 'MCPAuth.Client.Tests.pas';

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
