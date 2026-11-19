unit MCPAuth.OAuth.Pkce;

interface

type
  TPkce = record
  private
    class function AreAllCharactersAllowed(const Verifier: string): Boolean; static;

  public
    class function NewVerifier: string; static;
    class function ChallengeOf(const Verifier: string): string; static;
    class function Verify(const Verifier, Challenge: string): Boolean; static;
  end;

implementation

uses
  System.SysUtils,
  MCPAuth.Secret.Interfaces,
  MCPAuth.Secret.Hash,
  MCPAuth.Secret.Token;

const
  MinVerifierLength = 43;
  MaxVerifierLength = 128;

{ TPkce }

class function TPkce.AreAllCharactersAllowed(const Verifier: string): Boolean;
begin
  for var Character in Verifier do
  begin
    const IsLetterOrDigit = CharInSet(Character, ['A'..'Z', 'a'..'z', '0'..'9']);
    const IsPunctuation = CharInSet(Character, ['-', '.', '_', '~']);
    const IsAllowed = (IsLetterOrDigit or IsPunctuation);
    if not IsAllowed then
      Exit(False);
  end;

  Result := True;
end;

class function TPkce.NewVerifier: string;
begin
  // A random token is 43 base64url characters, which is the minimum length RFC 7636 allows.
  const Generator: ITokenGenerator = TTokenGenerator.Create;

  Result := Generator.NewToken;
end;

class function TPkce.ChallengeOf(const Verifier: string): string;
begin
  Result := TTokenHash.Of(Verifier);
end;

class function TPkce.Verify(const Verifier, Challenge: string): Boolean;
begin
  const HasValidLength = (Verifier.Length >= MinVerifierLength) and (Verifier.Length <= MaxVerifierLength);
  if not HasValidLength then
    Exit(False);

  if not AreAllCharactersAllowed(Verifier) then
    Exit(False);

  Result := TTokenHash.SameHash(ChallengeOf(Verifier), Challenge);
end;

end.
