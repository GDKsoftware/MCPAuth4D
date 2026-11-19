unit MCPAuth.OAuth.Pkce.Tests;

interface

uses
  DUnitX.TestFramework;

const
  Rfc7636Verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  Rfc7636Challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

type
  [TestFixture]
  TPkceTests = class
  public
    [Test]
    procedure S256VerifierMatchesRfc7636Example;

    [Test]
    procedure ChallengeOfMatchesRfc7636Example;

    [Test]
    procedure TooShortVerifierFails;

    [Test]
    procedure TooLongVerifierFails;

    [Test]
    procedure VerifierWithForbiddenCharacterFails;

    [Test]
    procedure WrongChallengeFails;

    [Test]
    procedure NewVerifierVerifiesAgainstItsChallenge;

    [Test]
    procedure NewVerifiersDiffer;
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.OAuth.Pkce;

{ TPkceTests }

procedure TPkceTests.S256VerifierMatchesRfc7636Example;
begin
  const Actual = TPkce.Verify(Rfc7636Verifier, Rfc7636Challenge);

  Assert.IsTrue(Actual);
end;

procedure TPkceTests.ChallengeOfMatchesRfc7636Example;
begin
  const Actual = TPkce.ChallengeOf(Rfc7636Verifier);

  Assert.AreEqual(Rfc7636Challenge, Actual);
end;

procedure TPkceTests.TooShortVerifierFails;
begin
  const Verifier = StringOfChar('a', 42);
  const Challenge = TPkce.ChallengeOf(Verifier);

  const Actual = TPkce.Verify(Verifier, Challenge);

  Assert.IsFalse(Actual);
end;

procedure TPkceTests.TooLongVerifierFails;
begin
  const Verifier = StringOfChar('a', 129);
  const Challenge = TPkce.ChallengeOf(Verifier);

  const Actual = TPkce.Verify(Verifier, Challenge);

  Assert.IsFalse(Actual);
end;

procedure TPkceTests.VerifierWithForbiddenCharacterFails;
begin
  const Verifier = StringOfChar('a', 42) + '+';
  const Challenge = TPkce.ChallengeOf(Verifier);

  const Actual = TPkce.Verify(Verifier, Challenge);

  Assert.IsFalse(Actual);
end;

procedure TPkceTests.WrongChallengeFails;
begin
  const Actual = TPkce.Verify(Rfc7636Verifier, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN');

  Assert.IsFalse(Actual);
end;

procedure TPkceTests.NewVerifierVerifiesAgainstItsChallenge;
begin
  const Verifier = TPkce.NewVerifier;
  const Challenge = TPkce.ChallengeOf(Verifier);

  const Actual = TPkce.Verify(Verifier, Challenge);

  Assert.IsTrue(Actual);
end;

procedure TPkceTests.NewVerifiersDiffer;
begin
  const First = TPkce.NewVerifier;
  const Second = TPkce.NewVerifier;

  Assert.AreNotEqual(First, Second);
end;

end.
