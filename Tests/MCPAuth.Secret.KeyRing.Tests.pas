unit MCPAuth.Secret.KeyRing.Tests;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  Spring.Collections,
  MCPAuth.Secret.Interfaces;

type
  [TestFixture]
  TKeyRingTests = class
  private
    FVariables: IDictionary<string, string>;

    function ReadVariable(const Name: string): string;
    function LoadKeyRing: IKeyRing;
    function KeyOf(const Value: Byte): TBytes;
    function Base64Of(const Bytes: TBytes): string;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure MissingKeyIdDefaultsToOne;

    [Test]
    procedure MasterKeyIsAvailableUnderItsKeyId;

    [Test]
    procedure PreviousKeysAreAvailable;

    [Test]
    procedure UnknownKeyIdIsNotFound;

    [Test]
    procedure MissingMasterKeyRaises;

    [Test]
    [TestCase('TooShort', 'AAAA')]
    [TestCase('NotBase64', '!!!!')]
    procedure InvalidMasterKeyRaises(const MasterKey: string);

    [Test]
    [TestCase('MissingSeparator', 'old')]
    [TestCase('EmptyKeyId', '=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=')]
    [TestCase('KeyTooShort', 'old=AAAA')]
    procedure InvalidPreviousKeysRaise(const PreviousKeys: string);
  end;

implementation

uses
  System.NetEncoding,
  MCPAuth.Secret.KeyRing;

const
  Prefix = 'TESTAUTH';
  MasterKeyVariable = 'TESTAUTH_MASTER_KEY';
  MasterKeyIdVariable = 'TESTAUTH_MASTER_KEY_ID';
  PreviousKeysVariable = 'TESTAUTH_PREVIOUS_KEYS';
  KeyLength = 32;
  NamedKeyId = '2026-11';

{ TKeyRingTests }

procedure TKeyRingTests.Setup;
begin
  const MasterKey = KeyOf(1);

  FVariables := TCollections.CreateDictionary<string, string>;
  FVariables[MasterKeyVariable] := Base64Of(MasterKey);
end;

procedure TKeyRingTests.TearDown;
begin
  FVariables := nil;
end;

function TKeyRingTests.ReadVariable(const Name: string): string;
begin
  if not FVariables.TryGetValue(Name, Result) then
    Result := '';
end;

function TKeyRingTests.LoadKeyRing: IKeyRing;
begin
  Result := TKeyRing.FromVariables(Prefix, ReadVariable);
end;

function TKeyRingTests.KeyOf(const Value: Byte): TBytes;
begin
  SetLength(Result, KeyLength);
  FillChar(Result[0], KeyLength, Value);
end;

function TKeyRingTests.Base64Of(const Bytes: TBytes): string;
begin
  Result := TNetEncoding.Base64String.EncodeBytesToString(Bytes);
end;

procedure TKeyRingTests.MissingKeyIdDefaultsToOne;
begin
  const KeyRing = LoadKeyRing;

  Assert.AreEqual('1', KeyRing.CurrentKeyId);
end;

procedure TKeyRingTests.MasterKeyIsAvailableUnderItsKeyId;
begin
  FVariables[MasterKeyIdVariable] := NamedKeyId;
  const Expected = KeyOf(1);

  const KeyRing = LoadKeyRing;
  var Key: TBytes;
  const Found = KeyRing.TryGetKey(NamedKeyId, Key);

  Assert.AreEqual(NamedKeyId, KeyRing.CurrentKeyId);
  Assert.IsTrue(Found);
  Assert.AreEqual<Byte>(Expected, Key);
end;

procedure TKeyRingTests.PreviousKeysAreAvailable;
begin
  const FirstExpected = KeyOf(7);
  const SecondExpected = KeyOf(8);
  const FirstEncoded = Base64Of(FirstExpected);
  const SecondEncoded = Base64Of(SecondExpected);
  FVariables[MasterKeyIdVariable] := '3';
  FVariables[PreviousKeysVariable] := Format('1=%s;2=%s', [FirstEncoded, SecondEncoded]);

  const KeyRing = LoadKeyRing;
  var FirstKey: TBytes;
  var SecondKey: TBytes;
  const FirstFound = KeyRing.TryGetKey('1', FirstKey);
  const SecondFound = KeyRing.TryGetKey('2', SecondKey);

  Assert.IsTrue(FirstFound);
  Assert.IsTrue(SecondFound);
  Assert.AreEqual<Byte>(FirstExpected, FirstKey);
  Assert.AreEqual<Byte>(SecondExpected, SecondKey);
end;

procedure TKeyRingTests.UnknownKeyIdIsNotFound;
begin
  const KeyRing = LoadKeyRing;
  var Key: TBytes;

  const Found = KeyRing.TryGetKey('unknown', Key);

  Assert.IsFalse(Found);
end;

procedure TKeyRingTests.MissingMasterKeyRaises;
begin
  FVariables.Remove(MasterKeyVariable);

  Assert.WillRaise(
    procedure
    begin
      LoadKeyRing;
    end,
    ESecretConfigurationError);
end;

procedure TKeyRingTests.InvalidMasterKeyRaises(const MasterKey: string);
begin
  FVariables[MasterKeyVariable] := MasterKey;

  Assert.WillRaise(
    procedure
    begin
      LoadKeyRing;
    end,
    ESecretConfigurationError);
end;

procedure TKeyRingTests.InvalidPreviousKeysRaise(const PreviousKeys: string);
begin
  FVariables[PreviousKeysVariable] := PreviousKeys;

  Assert.WillRaise(
    procedure
    begin
      LoadKeyRing;
    end,
    ESecretConfigurationError);
end;

end.
