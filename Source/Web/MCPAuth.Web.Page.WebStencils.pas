unit MCPAuth.Web.Page.WebStencils;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Contnrs,
  Web.Stencils,
  Spring.Collections,
  MCPAuth.Web.Page.Interfaces;

type
  TWebStencilsPageRenderer = class(TInterfacedObject, IPageRenderer)
  private
    FProjectTemplatesPath: string;
    FLibraryTemplatesPath: string;

    function LoadTemplate(const Template: string): string;
    function TryFindTemplateFile(const Template: string; out FilePath: string): Boolean;
    function IsPlainFileName(const Template: string): Boolean;
    procedure AddListVariables(const Processor: TWebStencilsProcessor; const Model: TObject; const Lists: IList<TObjectList>);
    procedure AddAccountLists(const Processor: TWebStencilsProcessor; const Model: TObject; const Lists: IList<TObjectList>);
    procedure HandleFile(Sender: TObject; const FileName: string; var Text: string; var Handled: Boolean);
    procedure HandleError(Sender: TObject; const Message: string);

  public
    constructor Create(const ProjectTemplatesPath, LibraryTemplatesPath: string);

    function Render(const Template: string; const Model: TObject): string;
  end;

implementation

uses
  System.IOUtils,
  MCPAuth.Web.Page.Exceptions,
  MCPAuth.Web.Page.Models;

const
  PageVariable = 'page';
  TemplateNotFoundMessage = 'Page template not found: %s';
  TemplateRenderFailedMessage = 'Page template error: %s';
  InvalidFileNameCharacters: array[0..2] of Char = ('/', '\', ':');

{ TWebStencilsPageRenderer }

constructor TWebStencilsPageRenderer.Create(const ProjectTemplatesPath, LibraryTemplatesPath: string);
begin
  inherited Create;
  FProjectTemplatesPath := ProjectTemplatesPath;
  FLibraryTemplatesPath := LibraryTemplatesPath;
end;

function TWebStencilsPageRenderer.Render(const Template: string; const Model: TObject): string;
begin
  const PageText = LoadTemplate(Template);
  const Lists = TCollections.CreateObjectList<TObjectList>(True);

  const Processor = TWebStencilsProcessor.Create(nil);
  try
    Processor.OnFile := HandleFile;
    Processor.OnError := HandleError;
    Processor.AddVar(PageVariable, Model, False);
    AddListVariables(Processor, Model, Lists);

    Result := Processor.ContentFromString(PageText);
  finally
    Processor.Free;
  end;
end;

function TWebStencilsPageRenderer.LoadTemplate(const Template: string): string;
begin
  var FilePath: string;
  const IsFound = TryFindTemplateFile(Template, FilePath);
  if not IsFound then
    raise EPageTemplateNotFound.CreateFmt(TemplateNotFoundMessage, [Template]);

  Result := TFile.ReadAllText(FilePath, TEncoding.UTF8);
end;

function TWebStencilsPageRenderer.TryFindTemplateFile(const Template: string; out FilePath: string): Boolean;
begin
  FilePath := '';
  Result := False;
  if not IsPlainFileName(Template) then
    Exit;

  for var Folder in [FProjectTemplatesPath, FLibraryTemplatesPath] do
  begin
    const HasFolder = not Folder.IsEmpty;
    const Candidate = TPath.Combine(Folder, Template);
    if HasFolder and TFile.Exists(Candidate) then
    begin
      FilePath := Candidate;
      Exit(True);
    end;
  end;
end;

function TWebStencilsPageRenderer.IsPlainFileName(const Template: string): Boolean;
begin
  const IsEmptyName = Template.Trim.IsEmpty;
  const HasPathCharacter = (Template.IndexOfAny(InvalidFileNameCharacters) >= 0);
  const IsParentReference = Template.Contains('..');
  Result := not (IsEmptyName or HasPathCharacter or IsParentReference);
end;

procedure TWebStencilsPageRenderer.AddListVariables(const Processor: TWebStencilsProcessor; const Model: TObject; const Lists: IList<TObjectList>);
begin
  if Model is TAccountPageModel then
    AddAccountLists(Processor, Model, Lists);
end;

procedure TWebStencilsPageRenderer.AddAccountLists(const Processor: TWebStencilsProcessor; const Model: TObject; const Lists: IList<TObjectList>);
begin
  const AccountModel = TAccountPageModel(Model);

  const Accounts = TObjectList.Create(False);
  Lists.Add(Accounts);
  for var Account in AccountModel.Accounts do
    Accounts.Add(Account);
  Processor.AddVar('accounts', Accounts, False);

  const Grants = TObjectList.Create(False);
  Lists.Add(Grants);
  for var Grant in AccountModel.Grants do
    Grants.Add(Grant);
  Processor.AddVar('grants', Grants, False);

  const Providers = TObjectList.Create(True);
  Lists.Add(Providers);
  for var Provider in AccountModel.Providers do
    Providers.Add(TProviderRow.Create(Provider));
  Processor.AddVar('providers', Providers, False);
end;

procedure TWebStencilsPageRenderer.HandleFile(Sender: TObject; const FileName: string; var Text: string; var Handled: Boolean);
begin
  Text := LoadTemplate(FileName);
  Handled := True;
end;

procedure TWebStencilsPageRenderer.HandleError(Sender: TObject; const Message: string);
begin
  raise EPageRenderFailed.CreateFmt(TemplateRenderFailedMessage, [Message]);
end;

end.
