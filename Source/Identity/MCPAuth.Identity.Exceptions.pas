unit MCPAuth.Identity.Exceptions;

interface

uses
  System.SysUtils;

type
  EAccountLinkedToOtherUser = class(Exception);
  EAccessDenied = class(Exception);
  EUserNotFound = class(Exception);

implementation

end.
