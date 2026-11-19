unit MCPAuth.Secret.Token.Tests;

interface

uses
  DUnitX.TestFramework,
  MCPAuth.Secret.Interfaces;

type
  [TestFixture]
  TTokenGeneratorTests = class
  private
    FGenerator: ITokenGenerator;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure TokenIsBase64UrlOf32Bytes;

    [Test]
    procedure TokensAreUnique;
  end;

implementation

uses
  System.RegularExpressions,
  Spring.Collections,
  MCPAuth.Secret.Token;

const
  Base64UrlOf32BytesPattern = '^[A-Za-z0-9_-]{43}$';
  UniqueTokenCount = 1000;

{ TTokenGeneratorTests }

procedure TTokenGeneratorTests.Setup;
begin
  FGenerator := TTokenGenerator.Create;
end;

procedure TTokenGeneratorTests.TearDown;
begin
  FGenerator := nil;
end;

procedure TTokenGeneratorTests.TokenIsBase64UrlOf32Bytes;
begin
  const Token = FGenerator.NewToken;

  const IsBase64UrlOf32Bytes = TRegEx.IsMatch(Token, Base64UrlOf32BytesPattern);
  Assert.IsTrue(IsBase64UrlOf32Bytes, 'Token must be 43 base64url characters without padding');
end;

procedure TTokenGeneratorTests.TokensAreUnique;
begin
  const Tokens = TCollections.CreateSet<string>;

  for var Index := 1 to UniqueTokenCount do
  begin
    const Token = FGenerator.NewToken;
    Tokens.Add(Token);
  end;

  Assert.AreEqual(UniqueTokenCount, Tokens.Count);
end;

end.
