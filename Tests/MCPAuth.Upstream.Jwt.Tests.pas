unit MCPAuth.Upstream.Jwt.Tests;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  TJwtPayloadTests = class
  public
    [Test]
    procedure DecodesPayloadOfUnsignedJwt;

    [Test]
    [TestCase('NoDots', 'abcdef')]
    [TestCase('TwoParts', 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0')]
    [TestCase('FourParts', 'a.eyJzdWIiOiIxIn0.c.d')]
    [TestCase('PayloadNotJson', 'eyJhbGciOiJub25lIn0.bm90LWpzb24.')]
    [TestCase('PayloadIsArray', 'eyJhbGciOiJub25lIn0.WzEsMl0.')]
    [TestCase('EmptyPayload', 'eyJhbGciOiJub25lIn0..')]
    procedure MalformedJwtRaises(const Jwt: string);
  end;

implementation

uses
  System.SysUtils,
  System.JSON,
  MCPAuth.Fakes.Jwt,
  MCPAuth.Upstream.Exceptions,
  MCPAuth.Upstream.Jwt;

{ TJwtPayloadTests }

procedure TJwtPayloadTests.DecodesPayloadOfUnsignedJwt;
begin
  const Jwt = TFakeJwt.Unsigned('{"sub":"user-1","name":"Ada Lovelace","n":42}');

  const Payload = TJwtPayload.Decode(Jwt);
  try
    Assert.AreEqual('user-1', Payload.GetValue<string>('sub'));
    Assert.AreEqual('Ada Lovelace', Payload.GetValue<string>('name'));
    Assert.AreEqual(42, Payload.GetValue<Integer>('n'));
  finally
    Payload.Free;
  end;
end;

procedure TJwtPayloadTests.MalformedJwtRaises(const Jwt: string);
begin
  var RaisedMessage := '';
  try
    TJwtPayload.Decode(Jwt).Free;
  except
    on E: EUpstreamTokenMalformed do
      RaisedMessage := E.Message;
  end;

  const HasRaised = not RaisedMessage.IsEmpty;
  Assert.IsTrue(HasRaised, 'Decode must raise EUpstreamTokenMalformed');
  Assert.DoesNotContain(RaisedMessage, Jwt);
end;

end.
