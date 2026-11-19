unit MCPAuth.Upstream.FormEncoding.Tests;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  TFormEncodingTests = class
  public
    [Test]
    procedure EncodesFieldsInOrderWithReservedCharacters;

    [Test]
    procedure NoFieldsGiveEmptyString;
  end;

implementation

uses
  Spring.Collections,
  MCPAuth.Upstream.FormEncoding;

{ TFormEncodingTests }

procedure TFormEncodingTests.EncodesFieldsInOrderWithReservedCharacters;
begin
  const Fields: TArray<TPair<string, string>> = [
    TPair<string, string>.Create('scope', 'openid Mail.Read'),
    TPair<string, string>.Create('redirect_uri', 'https://a.example/cb?x=1&y=2'),
    TPair<string, string>.Create('code', 'a+b/c=')
  ];

  const Encoded = TFormEncoding.Encode(Fields);

  Assert.AreEqual('scope=openid+Mail.Read&redirect_uri=https%3A%2F%2Fa.example%2Fcb%3Fx%3D1%26y%3D2&code=a%2Bb%2Fc%3D', Encoded);
end;

procedure TFormEncodingTests.NoFieldsGiveEmptyString;
begin
  const Encoded = TFormEncoding.Encode([]);

  Assert.IsEmpty(Encoded);
end;

end.
