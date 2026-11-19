unit MCPAuth.OAuth.RedirectPolicy.Tests;

interface

uses
  DUnitX.TestFramework,
  MCPAuth.OAuth.RedirectPolicy;

type
  [TestFixture]
  TRedirectPolicyTests = class
  private
    FPolicy: TRedirectPolicy;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    [TestCase('ClaudeAi', 'https://claude.ai/api/mcp/auth_callback')]
    [TestCase('ClaudeCom', 'https://claude.com/api/mcp/auth_callback')]
    [TestCase('ClaudeUpperCaseHost', 'https://CLAUDE.AI/api/mcp/auth_callback')]
    procedure ClaudeCallbackIsAllowed(const Uri: string);

    [Test]
    [TestCase('LocalhostPort', 'http://localhost:33418/callback')]
    [TestCase('LoopbackIpPort', 'http://127.0.0.1:8080/oauth/cb')]
    [TestCase('LocalhostOtherPort', 'http://localhost:1/x')]
    [TestCase('LocalhostUpperCase', 'http://LOCALHOST:5000/cb')]
    procedure LoopbackWithAnyPortIsAllowed(const Uri: string);

    [Test]
    [TestCase('HttpClaude', 'http://claude.ai/api/mcp/auth_callback')]
    [TestCase('HttpOtherHost', 'http://example.com/callback')]
    [TestCase('HttpsOtherHost', 'https://example.com/callback')]
    [TestCase('HttpsLoopback', 'https://localhost:8080/cb')]
    procedure HttpNonLoopbackIsRejected(const Uri: string);

    [Test]
    [TestCase('ClaudeFragment', 'https://claude.ai/api/mcp/auth_callback#x')]
    [TestCase('LoopbackFragment', 'http://localhost:8080/cb#x')]
    procedure UriWithFragmentIsRejected(const Uri: string);

    [Test]
    [TestCase('Suffix', 'https://claude.ai.evil.com/api/mcp/auth_callback')]
    [TestCase('Prefix', 'https://evilclaude.ai/api/mcp/auth_callback')]
    [TestCase('LoopbackSuffix', 'http://localhost.evil.com:8080/cb')]
    procedure LookalikeHostIsRejected(const Uri: string);

    [Test]
    [TestCase('ClaudeUserInfo', 'https://claude.ai@evil.com/api/mcp/auth_callback')]
    [TestCase('ClaudeUserInfoWithPassword', 'https://claude.ai:secret@claude.ai/api/mcp/auth_callback')]
    [TestCase('LoopbackUserInfo', 'http://localhost:8080@evil.com/cb')]
    procedure UriWithUserInfoIsRejected(const Uri: string);

    [Test]
    [TestCase('NoScheme', 'claude.ai/api/mcp/auth_callback')]
    [TestCase('NoPath', 'http://localhost:8080')]
    [TestCase('Backslash', 'http://localhost:8080\@evil.com/cb')]
    [TestCase('Whitespace', 'http://localhost:8080/cb x')]
    [TestCase('PortNotNumber', 'http://localhost:abc/cb')]
    [TestCase('PortTooLarge', 'http://localhost:70000/cb')]
    [TestCase('PortZero', 'http://localhost:0/cb')]
    [TestCase('ClaudeOtherPath', 'https://claude.ai/other')]
    [TestCase('ClaudeOtherPort', 'https://claude.ai:8443/api/mcp/auth_callback')]
    [TestCase('CustomScheme', 'myapp://localhost/cb')]
    procedure MalformedOrUnknownUriIsRejected(const Uri: string);

    [Test]
    procedure EmptyUriIsRejected;

    [Test]
    procedure ExtraUriIsAllowedExactly;

    [Test]
    procedure ExtraUriWithDifferentPathIsRejected;

    [Test]
    procedure ExtraUriWithUserInfoIsRejectedEvenWhenListed;
  end;

implementation

uses
  System.SysUtils;

const
  ExtraUri = 'https://app.example.com/oauth/callback';
  ExtraUriWithUserInfo = 'https://user@app.example.com/cb';

{ TRedirectPolicyTests }

procedure TRedirectPolicyTests.Setup;
begin
  FPolicy := TRedirectPolicy.Create([ExtraUri, ExtraUriWithUserInfo]);
end;

procedure TRedirectPolicyTests.TearDown;
begin
  FPolicy.Free;
end;

procedure TRedirectPolicyTests.ClaudeCallbackIsAllowed(const Uri: string);
begin
  Assert.IsTrue(FPolicy.IsAllowed(Uri));
end;

procedure TRedirectPolicyTests.LoopbackWithAnyPortIsAllowed(const Uri: string);
begin
  Assert.IsTrue(FPolicy.IsAllowed(Uri));
end;

procedure TRedirectPolicyTests.HttpNonLoopbackIsRejected(const Uri: string);
begin
  Assert.IsFalse(FPolicy.IsAllowed(Uri));
end;

procedure TRedirectPolicyTests.UriWithFragmentIsRejected(const Uri: string);
begin
  Assert.IsFalse(FPolicy.IsAllowed(Uri));
end;

procedure TRedirectPolicyTests.LookalikeHostIsRejected(const Uri: string);
begin
  Assert.IsFalse(FPolicy.IsAllowed(Uri));
end;

procedure TRedirectPolicyTests.UriWithUserInfoIsRejected(const Uri: string);
begin
  Assert.IsFalse(FPolicy.IsAllowed(Uri));
end;

procedure TRedirectPolicyTests.MalformedOrUnknownUriIsRejected(const Uri: string);
begin
  Assert.IsFalse(FPolicy.IsAllowed(Uri));
end;

procedure TRedirectPolicyTests.EmptyUriIsRejected;
begin
  Assert.IsFalse(FPolicy.IsAllowed(''));
end;

procedure TRedirectPolicyTests.ExtraUriIsAllowedExactly;
begin
  Assert.IsTrue(FPolicy.IsAllowed(ExtraUri));
end;

procedure TRedirectPolicyTests.ExtraUriWithDifferentPathIsRejected;
begin
  Assert.IsFalse(FPolicy.IsAllowed(ExtraUri + '/other'));
end;

procedure TRedirectPolicyTests.ExtraUriWithUserInfoIsRejectedEvenWhenListed;
begin
  Assert.IsFalse(FPolicy.IsAllowed(ExtraUriWithUserInfo));
end;

end.
