unit MCPAuth.Store.Memory.Tests;

interface

uses
  DUnitX.TestFramework,
  MCPAuth.Clock.Interfaces,
  MCPAuth.Store.Interfaces,
  MCPAuth.Store.Contract.Tests;

type
  [TestFixture]
  TMemoryStoreContractTests = class(TStoreContractTests)
  protected
    function CreateStore(const Clock: IClock): TStoreSet; override;
  end;

implementation

uses
  MCPAuth.Store.Memory;

{ TMemoryStoreContractTests }

function TMemoryStoreContractTests.CreateStore(const Clock: IClock): TStoreSet;
begin
  Result := TMemoryStore.CreateSet(Clock);
end;

end.
