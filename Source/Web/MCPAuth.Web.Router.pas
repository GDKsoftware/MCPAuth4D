unit MCPAuth.Web.Router;

interface

uses
  Spring.Collections,
  MCPAuth.Web.Types;

type
  // Routes are tried in registration order, so of two matching routes the first registered one wins.
  TWebRouter = class
  private type
    TRoute = record
      Method: string;
      Path: string;
      IsPrefix: Boolean;
      Handler: TWebHandler;

      function Matches(const Request: TWebRequest): Boolean;
    end;

  private
    FRoutes: IList<TRoute>;
    FNotFoundHandler: TWebHandler;

    class function JsonNotFound: TWebResponse; static;

    procedure AddRoute(const Method, Path: string; const IsPrefix: Boolean; const Handler: TWebHandler);
    function TryFindRoute(const Request: TWebRequest; out Route: TRoute): Boolean;

  public
    constructor Create;

    procedure Add(const Method, Path: string; const Handler: TWebHandler);
    procedure AddPrefix(const Method, Prefix: string; const Handler: TWebHandler);

    // Answers requests without a route; the first one set wins. Without one, such a request gets a JSON 404.
    procedure SetNotFound(const Handler: TWebHandler);

    function Dispatch(const Request: TWebRequest): TWebResponse; reintroduce;
  end;

implementation

uses
  System.SysUtils;

const
  StatusNotFound = 404;
  NotFoundErrorCode = 'not_found';

{ TWebRouter.TRoute }

function TWebRouter.TRoute.Matches(const Request: TWebRequest): Boolean;
begin
  const IsSameMethod = SameText(Method, Request.Method);
  if not IsSameMethod then
    Exit(False);

  if IsPrefix then
    Result := Request.Path.StartsWith(Path)
  else
    Result := (Request.Path = Path);
end;

{ TWebRouter }

class function TWebRouter.JsonNotFound: TWebResponse;
begin
  Result := TWebResponse.Error(StatusNotFound, NotFoundErrorCode, '');
end;

constructor TWebRouter.Create;
begin
  inherited Create;
  FRoutes := TCollections.CreateList<TRoute>;
end;

procedure TWebRouter.Add(const Method, Path: string; const Handler: TWebHandler);
begin
  AddRoute(Method, Path, False, Handler);
end;

procedure TWebRouter.AddPrefix(const Method, Prefix: string; const Handler: TWebHandler);
begin
  AddRoute(Method, Prefix, True, Handler);
end;

procedure TWebRouter.AddRoute(const Method, Path: string; const IsPrefix: Boolean; const Handler: TWebHandler);
begin
  var Route := Default(TRoute);
  Route.Method   := Method;
  Route.Path     := Path;
  Route.IsPrefix := IsPrefix;
  Route.Handler  := Handler;
  FRoutes.Add(Route);
end;

procedure TWebRouter.SetNotFound(const Handler: TWebHandler);
begin
  if not Assigned(FNotFoundHandler) then
    FNotFoundHandler := Handler;
end;

function TWebRouter.Dispatch(const Request: TWebRequest): TWebResponse;
begin
  var Route: TRoute;
  if TryFindRoute(Request, Route) then
    Result := Route.Handler(Request)
  else if Assigned(FNotFoundHandler) then
    Result := FNotFoundHandler(Request)
  else
    Result := JsonNotFound;
end;

function TWebRouter.TryFindRoute(const Request: TWebRequest; out Route: TRoute): Boolean;
begin
  for var Candidate in FRoutes do
  begin
    if Candidate.Matches(Request) then
    begin
      Route := Candidate;
      Exit(True);
    end;
  end;

  Route := Default(TRoute);
  Result := False;
end;

end.
