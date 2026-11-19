unit MCPAuth.Store.FireDAC.Exceptions;

interface

uses
  System.SysUtils;

type
  EFireDACStoreError = class(Exception);
  EMigrationError = class(EFireDACStoreError);

implementation

end.
