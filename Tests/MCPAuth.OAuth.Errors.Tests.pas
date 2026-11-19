unit MCPAuth.OAuth.Errors.Tests;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  TOAuthErrorTests = class
  public
    [Test]
    procedure InvalidClientHasStatus401;

    [Test]
    [TestCase('InvalidRequest', 'invalid_request')]
    [TestCase('InvalidGrant', 'invalid_grant')]
    [TestCase('InvalidRedirectUri', 'invalid_redirect_uri')]
    [TestCase('AccessDenied', 'access_denied')]
    procedure OtherCodesHaveStatus400(const ErrorCode: string);

    [Test]
    procedure KeepsCodeAndDescription;
  end;

  [TestFixture]
  TMCPAuthSettingsTests = class
  public
    [Test]
    procedure DefaultsMatchSpecification;
  end;

implementation

uses
  MCPAuth.OAuth.Errors,
  MCPAuth.OAuth.Settings;

{ TOAuthErrorTests }

procedure TOAuthErrorTests.InvalidClientHasStatus401;
begin
  const Error = EOAuthError.Create(TOAuthErrorCode.InvalidClient, 'Unknown client');
  try
    Assert.AreEqual(401, Error.StatusCode);
  finally
    Error.Free;
  end;
end;

procedure TOAuthErrorTests.OtherCodesHaveStatus400(const ErrorCode: string);
begin
  const Error = EOAuthError.Create(ErrorCode, 'Description');
  try
    Assert.AreEqual(400, Error.StatusCode);
  finally
    Error.Free;
  end;
end;

procedure TOAuthErrorTests.KeepsCodeAndDescription;
begin
  const Error = EOAuthError.Create(TOAuthErrorCode.InvalidScope, 'Scope not supported');
  try
    Assert.AreEqual('invalid_scope', Error.ErrorCode);
    Assert.AreEqual('Scope not supported', Error.Message);
  finally
    Error.Free;
  end;
end;

{ TMCPAuthSettingsTests }

procedure TMCPAuthSettingsTests.DefaultsMatchSpecification;
begin
  const Settings = TMCPAuthSettings.Defaults('https://auth.example.com');

  Assert.AreEqual('https://auth.example.com', Settings.Issuer);
  Assert.AreEqual('mcp', Settings.Scope);
  Assert.AreEqual(3600, Settings.AccessTokenSeconds);
  Assert.AreEqual(30, Settings.RefreshTokenDays);
  Assert.AreEqual(300, Settings.CodeSeconds);
  Assert.AreEqual(600, Settings.PendingSeconds);
  Assert.AreEqual(12, Settings.SessionHours);
  Assert.AreEqual(0, Integer(Length(Settings.ExtraRedirectUris)));
  Assert.IsTrue(Settings.SecureCookies);
  Assert.AreEqual(60, Settings.IntrospectionCacheSeconds);
end;

end.
