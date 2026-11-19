unit MCPAuth.Identity.Interfaces;

interface

uses
  Spring.Collections,
  MCPAuth.Identity.Types;

type
  IUserRepository = interface
    ['{0E7A4C21-8B35-4D96-A1F0-52C9D3B6E847}']
    function TryGet(const UserId: string; out User: TAuthUser): Boolean;
    procedure Save(const User: TAuthUser);
  end;

  ILinkedAccountRepository = interface
    ['{C3F18A5D-62B7-4E09-9A4C-7D1E5B8F2A60}']
    function TryFind(const Key: TAccountKey; out Account: TLinkedAccount): Boolean;
    function ListForUser(const UserId: string): IReadOnlyList<TLinkedAccount>;

    // Raises EAccountLinkedToOtherUser when the key belongs to another user.
    procedure Save(const Account: TLinkedAccount);
    procedure Delete(const UserId: string; const Key: TAccountKey);
  end;

implementation

end.
