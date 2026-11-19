unit MCPAuth.Secret.Interfaces;

interface

uses
  System.SysUtils;

type
  ESecretError = class(Exception);
  ESecretConfigurationError = class(ESecretError);
  ESecretUnprotectError = class(ESecretError);

  ITokenGenerator = interface
    ['{92658131-2E5D-4652-86B1-8BB3B48DA547}']
    function NewToken: string;
  end;

  IKeyRing = interface
    ['{B0EAED00-AF19-4EDC-B25C-8936EDE22DC6}']
    function TryGetKey(const KeyId: string; out Key: TBytes): Boolean;

    function GetCurrentKeyId: string;
    property CurrentKeyId: string read GetCurrentKeyId;
  end;

  ISecretProtector = interface
    ['{AEC42D93-0326-4194-836B-40D79B9DBAAB}']
    function Protect(const Plain, Context: string): TBytes;
    function Unprotect(const Envelope: TBytes; const Context: string): string;
    function NeedsRewrap(const Envelope: TBytes): Boolean;
  end;

implementation

end.
