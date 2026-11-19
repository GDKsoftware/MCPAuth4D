unit MCPAuth.Secret.AesGcm.Tests;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MCPAuth.Secret.Interfaces;

const
  SampleSecret = 'refresh-token-value';

type
  [TestFixture]
  TAesGcmProtectorTests = class
  private
    FProtector: ISecretProtector;

    function KeyOf(const Value: Byte): TBytes;
    function OriginalKeyRing: IKeyRing;
    function RotatedKeyRing: IKeyRing;
    function ProtectorFor(const KeyRing: IKeyRing): ISecretProtector;
    function Base64Of(const Bytes: TBytes): string;

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    [TestCase('Ascii', SampleSecret)]
    [TestCase('Empty', '')]
    procedure ProtectRoundTrips(const Plain: string);

    [Test]
    procedure ProtectRoundTripsUnicode;

    [Test]
    procedure EnvelopeHasVersionKeyIdNonceAndTag;

    [Test]
    procedure ProtectUsesFreshNonce;

    [Test]
    procedure WrongContextFails;

    [Test]
    procedure TamperedEnvelopeFails;

    [Test]
    procedure TruncatedEnvelopeFails;

    [Test]
    procedure UnknownVersionFails;

    [Test]
    procedure UnknownKeyIdFails;

    [Test]
    procedure PreviousKeyStillDecrypts;

    [Test]
    procedure NeedsRewrapAfterRotation;

    [Test]
    procedure CreateWithoutKeyRingRaises;
  end;

implementation

uses
  System.NetEncoding,
  Spring.Collections,
  MCPAuth.Secret.KeyRing,
  MCPAuth.Secret.AesGcm;

const
  Context = 'user-1|microsoft:tenant:object';
  OtherContext = 'user-2|microsoft:tenant:object';
  UnicodeSampleSecret = 'g'#$00E9#$00E9'n '#$20AC' '#$2713' '#$D83D#$DD11;
  KeyLength = 32;
  NonceLength = 12;
  TagLength = 16;
  EnvelopeVersion = 1;
  OriginalKeyId = '1';
  RotatedKeyId = '2';
  HeaderLength = 2 + Length(OriginalKeyId) + NonceLength;

{ TAesGcmProtectorTests }

procedure TAesGcmProtectorTests.Setup;
begin
  const KeyRing = OriginalKeyRing;
  FProtector := ProtectorFor(KeyRing);
end;

procedure TAesGcmProtectorTests.TearDown;
begin
  FProtector := nil;
end;

function TAesGcmProtectorTests.KeyOf(const Value: Byte): TBytes;
begin
  SetLength(Result, KeyLength);
  FillChar(Result[0], KeyLength, Value);
end;

function TAesGcmProtectorTests.OriginalKeyRing: IKeyRing;
begin
  const Keys = TCollections.CreateDictionary<string, TBytes>;
  Keys[OriginalKeyId] := KeyOf(1);

  Result := TKeyRing.Create(OriginalKeyId, Keys);
end;

function TAesGcmProtectorTests.RotatedKeyRing: IKeyRing;
begin
  const Keys = TCollections.CreateDictionary<string, TBytes>;
  Keys[OriginalKeyId] := KeyOf(1);
  Keys[RotatedKeyId] := KeyOf(2);

  Result := TKeyRing.Create(RotatedKeyId, Keys);
end;

function TAesGcmProtectorTests.ProtectorFor(const KeyRing: IKeyRing): ISecretProtector;
begin
  Result := TAesGcmProtector.Create(KeyRing);
end;

function TAesGcmProtectorTests.Base64Of(const Bytes: TBytes): string;
begin
  Result := TNetEncoding.Base64String.EncodeBytesToString(Bytes);
end;

procedure TAesGcmProtectorTests.ProtectRoundTrips(const Plain: string);
begin
  const Envelope = FProtector.Protect(Plain, Context);

  const Actual = FProtector.Unprotect(Envelope, Context);

  Assert.AreEqual(Plain, Actual);
end;

procedure TAesGcmProtectorTests.ProtectRoundTripsUnicode;
begin
  const Envelope = FProtector.Protect(UnicodeSampleSecret, Context);

  const Actual = FProtector.Unprotect(Envelope, Context);

  Assert.AreEqual(UnicodeSampleSecret, Actual);
end;

procedure TAesGcmProtectorTests.EnvelopeHasVersionKeyIdNonceAndTag;
begin
  const SecretBytes = TEncoding.UTF8.GetBytes(SampleSecret);
  const KeyIdBytes = TEncoding.UTF8.GetBytes(OriginalKeyId);
  const ExpectedLength = HeaderLength + Length(SecretBytes) + TagLength;

  const Envelope = FProtector.Protect(SampleSecret, Context);

  Assert.AreEqual(ExpectedLength, Length(Envelope));
  Assert.AreEqual<Byte>(EnvelopeVersion, Envelope[0]);
  Assert.AreEqual<Integer>(Length(KeyIdBytes), Envelope[1]);
  Assert.AreEqual<Byte>(KeyIdBytes[0], Envelope[2]);
end;

procedure TAesGcmProtectorTests.ProtectUsesFreshNonce;
begin
  const First = FProtector.Protect(SampleSecret, Context);
  const Second = FProtector.Protect(SampleSecret, Context);

  const AreDifferent = (Base64Of(First) <> Base64Of(Second));
  Assert.IsTrue(AreDifferent, 'Two envelopes of the same secret must differ');
end;

procedure TAesGcmProtectorTests.WrongContextFails;
begin
  const Envelope = FProtector.Protect(SampleSecret, Context);

  Assert.WillRaise(
    procedure
    begin
      FProtector.Unprotect(Envelope, OtherContext);
    end,
    ESecretUnprotectError);
end;

procedure TAesGcmProtectorTests.TamperedEnvelopeFails;
begin
  var Envelope := FProtector.Protect(SampleSecret, Context);
  Envelope[HeaderLength] := Envelope[HeaderLength] xor $01;

  Assert.WillRaise(
    procedure
    begin
      FProtector.Unprotect(Envelope, Context);
    end,
    ESecretUnprotectError);
end;

procedure TAesGcmProtectorTests.TruncatedEnvelopeFails;
begin
  const Envelope = FProtector.Protect(SampleSecret, Context);
  const Truncated = Copy(Envelope, 0, HeaderLength);

  Assert.WillRaise(
    procedure
    begin
      FProtector.Unprotect(Truncated, Context);
    end,
    ESecretUnprotectError);
end;

procedure TAesGcmProtectorTests.UnknownVersionFails;
begin
  var Envelope := FProtector.Protect(SampleSecret, Context);
  Envelope[0] := EnvelopeVersion + 1;

  Assert.WillRaise(
    procedure
    begin
      FProtector.Unprotect(Envelope, Context);
    end,
    ESecretUnprotectError);
end;

procedure TAesGcmProtectorTests.UnknownKeyIdFails;
begin
  const RotatedKeys = RotatedKeyRing;
  const RotatedProtector = ProtectorFor(RotatedKeys);
  const Envelope = RotatedProtector.Protect(SampleSecret, Context);

  Assert.WillRaise(
    procedure
    begin
      FProtector.Unprotect(Envelope, Context);
    end,
    ESecretUnprotectError);
end;

procedure TAesGcmProtectorTests.PreviousKeyStillDecrypts;
begin
  const Envelope = FProtector.Protect(SampleSecret, Context);
  const RotatedKeys = RotatedKeyRing;
  const RotatedProtector = ProtectorFor(RotatedKeys);

  const Actual = RotatedProtector.Unprotect(Envelope, Context);

  Assert.AreEqual(SampleSecret, Actual);
end;

procedure TAesGcmProtectorTests.NeedsRewrapAfterRotation;
begin
  const Envelope = FProtector.Protect(SampleSecret, Context);
  const RotatedKeys = RotatedKeyRing;
  const RotatedProtector = ProtectorFor(RotatedKeys);

  const NeedsRewrapBefore = FProtector.NeedsRewrap(Envelope);
  const NeedsRewrapAfter = RotatedProtector.NeedsRewrap(Envelope);
  const Plain = RotatedProtector.Unprotect(Envelope, Context);
  const RewrappedEnvelope = RotatedProtector.Protect(Plain, Context);
  const NeedsRewrapRewrapped = RotatedProtector.NeedsRewrap(RewrappedEnvelope);

  Assert.IsFalse(NeedsRewrapBefore);
  Assert.IsTrue(NeedsRewrapAfter);
  Assert.IsFalse(NeedsRewrapRewrapped);
end;

procedure TAesGcmProtectorTests.CreateWithoutKeyRingRaises;
begin
  Assert.WillRaise(
    procedure
    begin
      ProtectorFor(nil);
    end,
    ESecretConfigurationError,
    'GuardKeyRing must raise when no key ring is given');
end;

end.
