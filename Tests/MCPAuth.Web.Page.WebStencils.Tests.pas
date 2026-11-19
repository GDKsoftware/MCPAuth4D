unit MCPAuth.Web.Page.WebStencils.Tests;

interface

uses
  DUnitX.TestFramework,
  Spring.Collections,
  MCPAuth.Web.Page.Interfaces,
  MCPAuth.Web.Page.Models;

type
  [TestFixture]
  TWebStencilsPageRendererTests = class
  private
    FOwnedObjects: IList<TObject>;
    FLibraryPath: string;
    FProjectPath: string;

    function FindLibraryTemplatesPath: string;
    function CreateRenderer(const UseProjectTemplates: Boolean): IPageRenderer;
    function CreateAccountRow(const Value: string; const NeedsReconnect: Boolean): TAccountRow;
    function CreateGrantRow(const Value: string): TGrantRow;
    function CreateHostileAccountModel: TAccountPageModel;
    procedure AssertNothingRawIn(const Html: string);

  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;

    [Test]
    procedure RendersLibraryTemplateWhenProjectHasNone;

    [Test]
    procedure ProjectLayoutWrapsLibraryPage;

    [Test]
    procedure ProjectTemplateOverridesLibraryTemplate;

    [Test]
    procedure MissingTemplateRaises;

    [Test]
    procedure MissingTemplateMessageHoldsOnlyTheName;

    [Test]
    procedure TemplateNameWithPathSegmentIsRejected;

    [Test]
    procedure ClientNameIsHtmlEscaped;

    [Test]
    procedure ConsentPageEscapesEveryModelValue;

    [Test]
    procedure AccountPageEscapesEveryModelValue;

    [Test]
    procedure ErrorAndDonePagesEscapeTheMessage;

    [Test]
    procedure ConsentPageHasApproveAndDenyFormWithHiddenFields;

    [Test]
    procedure AccountPageListsAccountsGrantsAndProviders;

    [Test]
    procedure AccountPageShowsReconnectOnlyWhenNeeded;

    [Test]
    procedure DefaultTemplatesHaveNoExternalResources;
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  MCPAuth.Web.Page.Exceptions,
  MCPAuth.Web.Page.WebStencils;

const
  HostileValue = '<script>alert("x")</script>''&';
  RawScript = '<script>alert';
  EscapedScript = '&lt;script&gt;';

{ TWebStencilsPageRendererTests }

procedure TWebStencilsPageRendererTests.Setup;
begin
  FOwnedObjects := TCollections.CreateObjectList<TObject>(True);
  FLibraryPath := FindLibraryTemplatesPath;

  const RepositoryRoot = TPath.GetDirectoryName(FLibraryPath);
  FProjectPath := TPath.Combine(RepositoryRoot, 'Tests');
  FProjectPath := TPath.Combine(FProjectPath, 'fixtures');
  FProjectPath := TPath.Combine(FProjectPath, 'templates-project');
end;

procedure TWebStencilsPageRendererTests.TearDown;
begin
  FOwnedObjects := nil;
end;

function TWebStencilsPageRendererTests.FindLibraryTemplatesPath: string;
begin
  var Folder := TPath.GetDirectoryName(ParamStr(0));
  while not Folder.IsEmpty do
  begin
    const Candidate = TPath.Combine(Folder, 'templates');
    const HasDefaultLayout = TFile.Exists(TPath.Combine(Candidate, 'layout.html'));
    if HasDefaultLayout then
      Exit(Candidate);

    Folder := TPath.GetDirectoryName(Folder);
  end;

  raise Exception.Create('The templates folder of the repository was not found');
end;

function TWebStencilsPageRendererTests.CreateRenderer(const UseProjectTemplates: Boolean): IPageRenderer;
begin
  if UseProjectTemplates then
    Result := TWebStencilsPageRenderer.Create(FProjectPath, FLibraryPath)
  else
    Result := TWebStencilsPageRenderer.Create('', FLibraryPath);
end;

function TWebStencilsPageRendererTests.CreateAccountRow(const Value: string; const NeedsReconnect: Boolean): TAccountRow;
begin
  Result := TAccountRow.Create;
  FOwnedObjects.Add(Result);
  Result.Key := 'key-' + Value;
  Result.DisplayName := 'name-' + Value;
  Result.UserName := 'user-' + Value;
  Result.NeedsReconnect := NeedsReconnect;
end;

function TWebStencilsPageRendererTests.CreateGrantRow(const Value: string): TGrantRow;
begin
  Result := TGrantRow.Create;
  FOwnedObjects.Add(Result);
  Result.FamilyId := 'family-' + Value;
  Result.ResourceName := 'resource-' + Value;
  Result.ClientName := 'client-' + Value;
  Result.CreatedAt := 'created-' + Value;
end;

function TWebStencilsPageRendererTests.CreateHostileAccountModel: TAccountPageModel;
begin
  Result := TAccountPageModel.Create;
  FOwnedObjects.Add(Result);
  Result.Title := HostileValue;
  Result.Csrf := HostileValue;
  Result.UserDisplayName := HostileValue;

  const Account = TAccountRow.Create;
  FOwnedObjects.Add(Account);
  Account.Key := HostileValue;
  Account.DisplayName := HostileValue;
  Account.UserName := HostileValue;
  Account.NeedsReconnect := True;
  Result.Accounts := [Account];

  const Grant = TGrantRow.Create;
  FOwnedObjects.Add(Grant);
  Grant.FamilyId := HostileValue;
  Grant.ResourceName := HostileValue;
  Grant.ClientName := HostileValue;
  Grant.CreatedAt := HostileValue;
  Result.Grants := [Grant];

  Result.Providers := [HostileValue];
end;

procedure TWebStencilsPageRendererTests.AssertNothingRawIn(const Html: string);
begin
  Assert.IsFalse(Html.Contains(RawScript), 'a model value was written unescaped');
  Assert.IsFalse(Html.Contains(HostileValue), 'a model value was written unescaped');
  Assert.IsTrue(Html.Contains(EscapedScript), 'the escaped model value is missing');
end;

procedure TWebStencilsPageRendererTests.RendersLibraryTemplateWhenProjectHasNone;
begin
  const Renderer = CreateRenderer(False);
  const Model = TErrorPageModel.Create;
  FOwnedObjects.Add(Model);
  Model.Title := 'Problem';
  Model.Message := 'Something went wrong';

  const Html = Renderer.Render('error.html', Model);

  Assert.IsTrue(Html.Contains('Something went wrong'));
  Assert.IsTrue(Html.Contains('<title>Problem</title>'));
  Assert.IsTrue(Html.Contains('@media (prefers-color-scheme: dark)'));
  Assert.IsFalse(Html.Contains('PROJECT-LAYOUT'));
end;

procedure TWebStencilsPageRendererTests.ProjectLayoutWrapsLibraryPage;
begin
  const Renderer = CreateRenderer(True);
  const Model = TDonePageModel.Create;
  FOwnedObjects.Add(Model);
  Model.Message := 'Library page body';

  const Html = Renderer.Render('done.html', Model);

  Assert.IsTrue(Html.Contains('PROJECT-LAYOUT'));
  Assert.IsTrue(Html.Contains('Library page body'));
end;

procedure TWebStencilsPageRendererTests.ProjectTemplateOverridesLibraryTemplate;
begin
  const Renderer = CreateRenderer(True);
  const Model = TErrorPageModel.Create;
  FOwnedObjects.Add(Model);
  Model.Message := 'Overridden';

  const Html = Renderer.Render('error.html', Model);

  Assert.IsTrue(Html.Contains('PROJECT-ERROR Overridden'));
end;

procedure TWebStencilsPageRendererTests.MissingTemplateRaises;
begin
  const Renderer = CreateRenderer(True);
  const Model = TPageModel.Create;
  FOwnedObjects.Add(Model);

  Assert.WillRaise(
    procedure
    begin
      Renderer.Render('missing.html', Model);
    end,
    EPageTemplateNotFound);
end;

procedure TWebStencilsPageRendererTests.MissingTemplateMessageHoldsOnlyTheName;
begin
  const Renderer = CreateRenderer(True);
  const Model = TPageModel.Create;
  FOwnedObjects.Add(Model);
  var Message := '';

  try
    Renderer.Render('missing.html', Model);
  except
    on E: EPageTemplateNotFound do
      Message := E.Message;
  end;

  Assert.IsTrue(Message.Contains('missing.html'));
  Assert.IsFalse(Message.Contains(FLibraryPath));
  Assert.IsFalse(Message.Contains(FProjectPath));
end;

procedure TWebStencilsPageRendererTests.TemplateNameWithPathSegmentIsRejected;
begin
  const Renderer = CreateRenderer(True);
  const Model = TPageModel.Create;
  FOwnedObjects.Add(Model);

  Assert.WillRaise(
    procedure
    begin
      Renderer.Render('../layout.html', Model);
    end,
    EPageTemplateNotFound);
end;

procedure TWebStencilsPageRendererTests.ClientNameIsHtmlEscaped;
begin
  const Renderer = CreateRenderer(False);
  const Model = TConsentPageModel.Create;
  FOwnedObjects.Add(Model);
  Model.ClientName := '<script>alert(1)</script>';

  const Html = Renderer.Render('consent.html', Model);

  Assert.IsFalse(Html.Contains('<script>alert(1)'));
  Assert.IsTrue(Html.Contains('&lt;script&gt;alert(1)&lt;/script&gt;'));
end;

procedure TWebStencilsPageRendererTests.ConsentPageEscapesEveryModelValue;
begin
  const Renderer = CreateRenderer(False);
  const Model = TConsentPageModel.Create;
  FOwnedObjects.Add(Model);
  Model.Title := HostileValue;
  Model.Csrf := HostileValue;
  Model.ClientName := HostileValue;
  Model.RedirectHost := HostileValue;
  Model.ResourceName := HostileValue;
  Model.PendingId := HostileValue;

  const Html = Renderer.Render('consent.html', Model);

  AssertNothingRawIn(Html);
end;

procedure TWebStencilsPageRendererTests.AccountPageEscapesEveryModelValue;
begin
  const Renderer = CreateRenderer(False);
  const Model = CreateHostileAccountModel;

  const Html = Renderer.Render('account.html', Model);

  AssertNothingRawIn(Html);
end;

procedure TWebStencilsPageRendererTests.ErrorAndDonePagesEscapeTheMessage;
begin
  const Renderer = CreateRenderer(False);
  const ErrorModel = TErrorPageModel.Create;
  FOwnedObjects.Add(ErrorModel);
  ErrorModel.Title := HostileValue;
  ErrorModel.Message := HostileValue;
  const DoneModel = TDonePageModel.Create;
  FOwnedObjects.Add(DoneModel);
  DoneModel.Title := HostileValue;
  DoneModel.Message := HostileValue;

  const ErrorHtml = Renderer.Render('error.html', ErrorModel);
  const DoneHtml = Renderer.Render('done.html', DoneModel);

  AssertNothingRawIn(ErrorHtml);
  AssertNothingRawIn(DoneHtml);
end;

procedure TWebStencilsPageRendererTests.ConsentPageHasApproveAndDenyFormWithHiddenFields;
begin
  const Renderer = CreateRenderer(False);
  const Model = TConsentPageModel.Create;
  FOwnedObjects.Add(Model);
  Model.Csrf := 'csrf-value';
  Model.PendingId := 'pending-value';
  Model.ClientName := 'Example Client';
  Model.RedirectHost := 'client.example';
  Model.ResourceName := 'Example Resource';

  const Html = Renderer.Render('consent.html', Model);

  Assert.IsTrue(Html.Contains('method="post" action="/consent"'));
  Assert.IsTrue(Html.Contains('name="pending" value="pending-value"'));
  Assert.IsTrue(Html.Contains('name="csrf" value="csrf-value"'));
  Assert.IsTrue(Html.Contains('name="decision" value="approve"'));
  Assert.IsTrue(Html.Contains('name="decision" value="deny"'));
  Assert.IsTrue(Html.Contains('Example Client'));
  Assert.IsTrue(Html.Contains('client.example'));
  Assert.IsTrue(Html.Contains('Example Resource'));
end;

procedure TWebStencilsPageRendererTests.AccountPageListsAccountsGrantsAndProviders;
begin
  const Renderer = CreateRenderer(False);
  const Model = TAccountPageModel.Create;
  FOwnedObjects.Add(Model);
  Model.Csrf := 'csrf-value';
  Model.UserDisplayName := 'Pat Example';
  Model.Accounts := [CreateAccountRow('a', False), CreateAccountRow('b', False)];
  Model.Grants := [CreateGrantRow('g1'), CreateGrantRow('g2')];
  Model.Providers := ['alpha', 'beta'];

  const Html = Renderer.Render('account.html', Model);

  Assert.IsTrue(Html.Contains('Pat Example'));
  Assert.IsTrue(Html.Contains('user-a'));
  Assert.IsTrue(Html.Contains('user-b'));
  Assert.IsTrue(Html.Contains('action="/account/unlink"'));
  Assert.IsTrue(Html.Contains('name="key" value="key-a"'));
  Assert.IsTrue(Html.Contains('action="/account/revoke"'));
  Assert.IsTrue(Html.Contains('name="family" value="family-g2"'));
  Assert.IsTrue(Html.Contains('resource-g1'));
  Assert.IsTrue(Html.Contains('action="/account/link"'));
  Assert.IsTrue(Html.Contains('name="provider" value="beta"'));
  Assert.IsTrue(Html.Contains('action="/logout"'));
  Assert.IsFalse(Html.Contains('name="csrf" value=""'));
end;

procedure TWebStencilsPageRendererTests.AccountPageShowsReconnectOnlyWhenNeeded;
begin
  const Renderer = CreateRenderer(False);
  const Model = TAccountPageModel.Create;
  FOwnedObjects.Add(Model);
  Model.Accounts := [CreateAccountRow('ok', False), CreateAccountRow('broken', True)];

  const Html = Renderer.Render('account.html', Model);

  const ReconnectForms = Html.Split(['action="/account/reconnect"']);
  Assert.AreEqual<Integer>(2, Length(ReconnectForms), 'exactly one reconnect form is expected');
  Assert.IsTrue(ReconnectForms[1].Contains('key-broken'));
end;

procedure TWebStencilsPageRendererTests.DefaultTemplatesHaveNoExternalResources;
begin
  for var Template in ['layout.html', 'consent.html', 'account.html', 'error.html', 'done.html', 'login.html'] do
  begin
    const Source = TFile.ReadAllText(TPath.Combine(FLibraryPath, Template), TEncoding.UTF8);

    Assert.IsFalse(Source.Contains('http://'), Template);
    Assert.IsFalse(Source.Contains('https://'), Template);
  end;
end;

end.
