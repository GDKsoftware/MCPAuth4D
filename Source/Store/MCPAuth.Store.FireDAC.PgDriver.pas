unit MCPAuth.Store.FireDAC.PgDriver;

interface

uses
  FireDAC.Phys.PG;

type
  // Links the FireDAC PostgreSQL driver into the program and tells it where libpq is.
  // Keep the instance alive as long as connections are made.
  TFireDACPgDriver = class
  private
    FLink: TFDPhysPgDriverLink;

  public
    // An empty VendorLib uses the platform default: libpq.dll on the PATH on Windows, libpq.so.5 on Linux.
    constructor Create(const VendorLib: string = '');
    destructor Destroy; override;
  end;

implementation

uses
  System.SysUtils,
  FireDAC.Phys.PGDef;

const
{$IFDEF MSWINDOWS}
  DefaultVendorLib = 'libpq.dll';
{$ELSE}
  DefaultVendorLib = 'libpq.so.5';
{$ENDIF}

{ TFireDACPgDriver }

constructor TFireDACPgDriver.Create(const VendorLib: string);
begin
  inherited Create;

  FLink := TFDPhysPgDriverLink.Create(nil);
  if VendorLib.IsEmpty then
  begin
    FLink.VendorLib := DefaultVendorLib;
  end
  else
  begin
    FLink.VendorLib := VendorLib;
  end;
end;

destructor TFireDACPgDriver.Destroy;
begin
  FLink.Free;
  inherited Destroy;
end;

end.
