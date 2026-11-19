unit MCPAuth.Store.FireDAC.Interfaces;

interface

uses
  FireDAC.Comp.Client;

type
  IFireDACConnectionFactory = interface
    ['{6B2E9D41-0C7A-4F53-9E18-A4D35C7B20F6}']
    // Returns an open connection that the caller frees; freeing a pooled connection hands it back to the pool.
    // A connection is used by one thread only.
    function NewConnection: TFDConnection;
  end;

implementation

end.
