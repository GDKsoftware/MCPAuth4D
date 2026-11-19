unit MCPAuth.Secret.Hash.Tests;

interface

uses
  DUnitX.TestFramework;

const
  HashOfAbc = 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0';

type
  [TestFixture]
  TTokenHashTests = class
  public
    [Test]
    procedure HashOfKnownValue;

    [Test]
    [TestCase('Equal', HashOfAbc + ',' + HashOfAbc + ',True')]
    [TestCase('LastCharacterDiffers', HashOfAbc + ',ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa1,False')]
    [TestCase('LengthDiffers', HashOfAbc + ',ungWv48Bz,False')]
    [TestCase('BothEmpty', ',,True')]
    procedure SameHashComparesWholeValue(const A, B: string; const Expected: Boolean);
  end;

implementation

uses
  MCPAuth.Secret.Hash;

{ TTokenHashTests }

procedure TTokenHashTests.HashOfKnownValue;
begin
  const Actual = TTokenHash.Of('abc');

  Assert.AreEqual(HashOfAbc, Actual);
end;

procedure TTokenHashTests.SameHashComparesWholeValue(const A, B: string; const Expected: Boolean);
begin
  const Actual = TTokenHash.SameHash(A, B);

  Assert.AreEqual(Expected, Actual);
end;

end.
