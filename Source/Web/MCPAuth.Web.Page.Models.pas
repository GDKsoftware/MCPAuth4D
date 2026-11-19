unit MCPAuth.Web.Page.Models;

interface

type
  TPageModel = class
  private
    FTitle: string;
    FCsrf: string;

  public
    property Title: string read FTitle write FTitle;
    property Csrf: string read FCsrf write FCsrf;
  end;

  TConsentPageModel = class(TPageModel)
  private
    FClientName: string;
    FRedirectHost: string;
    FResourceName: string;
    FPendingId: string;

  public
    property ClientName: string read FClientName write FClientName;
    property RedirectHost: string read FRedirectHost write FRedirectHost;
    property ResourceName: string read FResourceName write FResourceName;
    property PendingId: string read FPendingId write FPendingId;
  end;

  TAccountRow = class
  private
    FKey: string;
    FDisplayName: string;
    FUserName: string;
    FNeedsReconnect: Boolean;

  public
    property Key: string read FKey write FKey;
    property DisplayName: string read FDisplayName write FDisplayName;
    property UserName: string read FUserName write FUserName;
    property NeedsReconnect: Boolean read FNeedsReconnect write FNeedsReconnect;
  end;

  TGrantRow = class
  private
    FFamilyId: string;
    FResourceName: string;
    FClientName: string;
    FCreatedAt: string;

  public
    property FamilyId: string read FFamilyId write FFamilyId;
    property ResourceName: string read FResourceName write FResourceName;
    property ClientName: string read FClientName write FClientName;
    property CreatedAt: string read FCreatedAt write FCreatedAt;
  end;

  TProviderRow = class
  private
    FName: string;

  public
    constructor Create(const Name: string);

    property Name: string read FName;
  end;

  TAccountPageModel = class(TPageModel)
  private
    FUserDisplayName: string;
    FAccounts: TArray<TAccountRow>;
    FGrants: TArray<TGrantRow>;
    FProviders: TArray<string>;

  public
    property UserDisplayName: string read FUserDisplayName write FUserDisplayName;
    property Accounts: TArray<TAccountRow> read FAccounts write FAccounts;
    property Grants: TArray<TGrantRow> read FGrants write FGrants;
    property Providers: TArray<string> read FProviders write FProviders;
  end;

  TLoginPageModel = class(TPageModel)
  private
    FProviders: TArray<string>;

  public
    property Providers: TArray<string> read FProviders write FProviders;
  end;

  TErrorPageModel = class(TPageModel)
  private
    FMessage: string;

  public
    property Message: string read FMessage write FMessage;
  end;

  TDonePageModel = class(TPageModel)
  private
    FMessage: string;

  public
    property Message: string read FMessage write FMessage;
  end;

implementation

{ TProviderRow }

constructor TProviderRow.Create(const Name: string);
begin
  inherited Create;
  FName := Name;
end;

end.
