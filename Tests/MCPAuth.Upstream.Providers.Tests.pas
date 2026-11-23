unit MCPAuth.Upstream.Providers.Tests;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  TUpstreamProvidersTests = class
  public
    [Test]
    procedure TryGetFindsProviderByName;

    [Test]
    procedure TryGetIgnoresCase;

    [Test]
    procedure TryGetOfUnknownNameFails;

    [Test]
    procedure NamesKeepRegistrationOrder;

    [Test]
    procedure DuplicateNameRaises;

    [Test]
    procedure NameWithAccountKeySeparatorRaises;
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Upstream.Interfaces,
  MCPAuth.Upstream.Providers,
  MCPAuth.Fakes.UpstreamProvider;

{ TUpstreamProvidersTests }

procedure TUpstreamProvidersTests.TryGetFindsProviderByName;
begin
  const First: IUpstreamProvider = TFakeUpstreamProvider.Create('first');
  const Second: IUpstreamProvider = TFakeUpstreamProvider.Create('second');
  const Providers: IUpstreamProviders = TUpstreamProviders.Create([First, Second]);

  var Found: IUpstreamProvider;
  const IsFound = Providers.TryGet('second', Found);

  Assert.IsTrue(IsFound);
  Assert.AreEqual('second', Found.Name);
end;

procedure TUpstreamProvidersTests.TryGetIgnoresCase;
begin
  const Provider: IUpstreamProvider = TFakeUpstreamProvider.Create('microsoft');
  const Providers: IUpstreamProviders = TUpstreamProviders.Create([Provider]);

  var Found: IUpstreamProvider;
  const IsFound = Providers.TryGet('Microsoft', Found);

  Assert.IsTrue(IsFound);
end;

procedure TUpstreamProvidersTests.TryGetOfUnknownNameFails;
begin
  const Provider: IUpstreamProvider = TFakeUpstreamProvider.Create('first');
  const Providers: IUpstreamProviders = TUpstreamProviders.Create([Provider]);

  var Found: IUpstreamProvider;
  const IsFound = Providers.TryGet('unknown', Found);

  Assert.IsFalse(IsFound);
  Assert.IsNull(Found);
end;

procedure TUpstreamProvidersTests.NamesKeepRegistrationOrder;
begin
  const First: IUpstreamProvider = TFakeUpstreamProvider.Create('zeta');
  const Second: IUpstreamProvider = TFakeUpstreamProvider.Create('alpha');
  const Providers: IUpstreamProviders = TUpstreamProviders.Create([First, Second]);

  const Names = Providers.Names;

  Assert.AreEqual<Integer>(2, Length(Names));
  Assert.AreEqual('zeta', Names[0]);
  Assert.AreEqual('alpha', Names[1]);
end;

procedure TUpstreamProvidersTests.DuplicateNameRaises;
begin
  const First: IUpstreamProvider = TFakeUpstreamProvider.Create('same');
  const Second: IUpstreamProvider = TFakeUpstreamProvider.Create('Same');
  const Duplicates: TArray<IUpstreamProvider> = [First, Second];

  Assert.WillRaise(
    procedure
    begin
      TUpstreamProviders.Create(Duplicates).Free;
    end,
    EArgumentException);
end;

procedure TUpstreamProvidersTests.NameWithAccountKeySeparatorRaises;
begin
  const Provider: IUpstreamProvider = TFakeUpstreamProvider.Create('acme:eu');
  const Providers: TArray<IUpstreamProvider> = [Provider];

  Assert.WillRaise(
    procedure
    begin
      TUpstreamProviders.Create(Providers).Free;
    end,
    EArgumentException);
end;

end.
