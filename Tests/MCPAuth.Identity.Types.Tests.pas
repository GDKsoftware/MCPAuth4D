unit MCPAuth.Identity.Types.Tests;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  TAccountKeyTests = class
  public
    [Test]
    procedure AccountKeyValueIsLowercaseAndColonSeparated;

    [Test]
    procedure AccountKeysWithSameValueAreEqual;
  end;

implementation

uses
  MCPAuth.Identity.Types;

{ TAccountKeyTests }

procedure TAccountKeyTests.AccountKeyValueIsLowercaseAndColonSeparated;
begin
  var Key: TAccountKey;
  Key.Provider := 'Microsoft';
  Key.TenantId := 'T1';
  Key.ObjectId := 'O1';

  const Actual = Key.Value;

  Assert.AreEqual('microsoft:t1:o1', Actual);
end;

procedure TAccountKeyTests.AccountKeysWithSameValueAreEqual;
begin
  var First: TAccountKey;
  First.Provider := 'Microsoft';
  First.TenantId := 'T1';
  First.ObjectId := 'O1';
  var Second: TAccountKey;
  Second.Provider := 'microsoft';
  Second.TenantId := 't1';
  Second.ObjectId := 'o1';

  Assert.AreEqual(First.Value, Second.Value);
end;

end.
