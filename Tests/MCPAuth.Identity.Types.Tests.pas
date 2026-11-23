unit MCPAuth.Identity.Types.Tests;

interface

uses
  DUnitX.TestFramework,
  MCPAuth.Identity.Types;

type
  [TestFixture]
  TAccountKeyTests = class
  private
    class function KeyOf(const Provider, TenantId, ObjectId: string): TAccountKey; static;

  public
    [Test]
    procedure ValueFoldsProviderAndTenantButKeepsObjectIdCase;

    [Test]
    procedure ValueFoldsGuidObjectId;

    [Test]
    procedure KeysDifferingOnlyInProviderOrTenantCaseAreEqual;

    [Test]
    procedure ObjectIdsDifferingOnlyInCaseGiveDifferentValues;

    [Test]
    [TestCase('Plain', 'acme,,00u1AbcDEF')]
    [TestCase('ColonsInObjectId', 'acme,,f:realm:Carol')]
    [TestCase('LeadingAndTrailingColon', 'acme,,:carol:')]
    [TestCase('WithTenant', 'acme,tenant-1,x:y')]
    procedure TryParseReturnsThePartsOfValue(const Provider, TenantId, ObjectId: string);

    [Test]
    [TestCase('NoSeparator', 'acme')]
    [TestCase('OneSeparator', 'acme:carol')]
    [TestCase('Empty', '')]
    procedure TryParseOfValueWithoutTwoSeparatorsFails(const Value: string);
  end;

implementation

uses
  System.SysUtils;

const
  MixedCaseObjectId: string = '00u1AbcDEF';

{ TAccountKeyTests }

class function TAccountKeyTests.KeyOf(const Provider, TenantId, ObjectId: string): TAccountKey;
begin
  Result.Provider := Provider;
  Result.TenantId := TenantId;
  Result.ObjectId := ObjectId;
end;

procedure TAccountKeyTests.ValueFoldsProviderAndTenantButKeepsObjectIdCase;
begin
  const Key = KeyOf('Acme', 'T1', MixedCaseObjectId);

  const Actual = Key.Value;

  Assert.AreEqual(Format('acme:t1:%s', [MixedCaseObjectId]), Actual, False);
end;

procedure TAccountKeyTests.ValueFoldsGuidObjectId;
begin
  const Key = KeyOf('Microsoft', '72F988BF-86F1-41AF-91AB-2D7CD011DB47', '0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9');

  const Actual = Key.Value;

  Assert.AreEqual('microsoft:72f988bf-86f1-41af-91ab-2d7cd011db47:0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9', Actual, False);
end;

procedure TAccountKeyTests.KeysDifferingOnlyInProviderOrTenantCaseAreEqual;
begin
  const First = KeyOf('Microsoft', 'T1', 'object-1');
  const Second = KeyOf('microsoft', 't1', 'object-1');

  Assert.AreEqual(First.Value, Second.Value, False);
end;

procedure TAccountKeyTests.ObjectIdsDifferingOnlyInCaseGiveDifferentValues;
begin
  const First = KeyOf('acme', '', MixedCaseObjectId);
  const Second = KeyOf('acme', '', MixedCaseObjectId.ToLowerInvariant);

  Assert.AreNotEqual(First.Value, Second.Value, False);
end;

procedure TAccountKeyTests.TryParseReturnsThePartsOfValue(const Provider, TenantId, ObjectId: string);
begin
  const Original = KeyOf(Provider, TenantId, ObjectId);

  var Parsed: TAccountKey;
  const IsParsed = TAccountKey.TryParse(Original.Value, Parsed);

  Assert.IsTrue(IsParsed);
  Assert.AreEqual(Provider, Parsed.Provider, False);
  Assert.AreEqual(TenantId, Parsed.TenantId, False);
  Assert.AreEqual(ObjectId, Parsed.ObjectId, False);
end;

procedure TAccountKeyTests.TryParseOfValueWithoutTwoSeparatorsFails(const Value: string);
begin
  var Parsed: TAccountKey;
  const IsParsed = TAccountKey.TryParse(Value, Parsed);

  Assert.IsFalse(IsParsed);
end;

end.
