unit MCPAuth.Fakes.LoginIdentities;

interface

uses
  Spring.Collections,
  MCPAuth.Identity.Types,
  MCPAuth.Identity.Interfaces;

type
  // Wraps a real repository. While a winner is set, the next new identity loses a race against another process:
  // the identity is saved for the winner instead, and the save raises ELoginIdentityTaken.
  TRacingLoginIdentityRepository = class(TInterfacedObject, ILoginIdentityRepository)
  private
    FInner: ILoginIdentityRepository;
    FWinnerUserId: string;
    FLosingUserId: string;

  public
    constructor Create(const Inner: ILoginIdentityRepository);

    function TryFind(const Key: TAccountKey; out Identity: TLoginIdentity): Boolean;
    function ListForUser(const UserId: string): IReadOnlyList<TLoginIdentity>;
    procedure Save(const Identity: TLoginIdentity);

    property WinnerUserId: string read FWinnerUserId write FWinnerUserId;
    property LosingUserId: string read FLosingUserId;
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Identity.Exceptions;

{ TRacingLoginIdentityRepository }

constructor TRacingLoginIdentityRepository.Create(const Inner: ILoginIdentityRepository);
begin
  inherited Create;

  FInner := Inner;
end;

function TRacingLoginIdentityRepository.TryFind(const Key: TAccountKey; out Identity: TLoginIdentity): Boolean;
begin
  Result := FInner.TryFind(Key, Identity);
end;

function TRacingLoginIdentityRepository.ListForUser(const UserId: string): IReadOnlyList<TLoginIdentity>;
begin
  Result := FInner.ListForUser(UserId);
end;

procedure TRacingLoginIdentityRepository.Save(const Identity: TLoginIdentity);
begin
  const IsRacing = not FWinnerUserId.IsEmpty;
  if not IsRacing then
  begin
    FInner.Save(Identity);
    Exit;
  end;

  var Winning := Identity;
  Winning.UserId := FWinnerUserId;
  FInner.Save(Winning);

  FLosingUserId := Identity.UserId;
  FWinnerUserId := '';
  raise ELoginIdentityTaken.Create('The account is already the login identity of another user');
end;

end.
