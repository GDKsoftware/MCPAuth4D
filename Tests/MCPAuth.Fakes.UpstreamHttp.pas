unit MCPAuth.Fakes.UpstreamHttp;

interface

uses
  Spring.Collections,
  MCPAuth.Upstream.Http.Interfaces;

type
  TRecordedUpstreamRequest = record
    Url: string;
    Fields: TArray<TPair<string, string>>;

    function HasField(const Name: string): Boolean;
    function GetField(const Name: string): string;
  end;

  TFakeUpstreamHttp = class(TInterfacedObject, IUpstreamHttp)
  private
    FResponses: IQueue<TUpstreamHttpResponse>;
    FRequests: IList<TRecordedUpstreamRequest>;

  public
    constructor Create;

    function PostForm(const Url: string; const Fields: TArray<TPair<string, string>>): TUpstreamHttpResponse;

    procedure EnqueueResponse(const StatusCode: Integer; const Body: string);
    function LastRequest: TRecordedUpstreamRequest;
    function RequestCount: Integer;
  end;

implementation

uses
  System.SysUtils;

resourcestring
  FieldNotFound = 'The recorded request has no field "%s"';
  NoCannedResponse = 'The fake upstream HTTP has no canned response left';
  NoRequestRecorded = 'The fake upstream HTTP has not received a request';

{ TRecordedUpstreamRequest }

function TRecordedUpstreamRequest.HasField(const Name: string): Boolean;
begin
  for var Field in Fields do
  begin
    if Field.Key = Name then
      Exit(True);
  end;

  Result := False;
end;

function TRecordedUpstreamRequest.GetField(const Name: string): string;
begin
  for var Field in Fields do
  begin
    if Field.Key = Name then
      Exit(Field.Value);
  end;

  raise EArgumentException.CreateFmt(FieldNotFound, [Name]);
end;

{ TFakeUpstreamHttp }

constructor TFakeUpstreamHttp.Create;
begin
  inherited Create;
  FResponses := TCollections.CreateQueue<TUpstreamHttpResponse>;
  FRequests  := TCollections.CreateList<TRecordedUpstreamRequest>;
end;

function TFakeUpstreamHttp.PostForm(const Url: string; const Fields: TArray<TPair<string, string>>): TUpstreamHttpResponse;
begin
  var Request: TRecordedUpstreamRequest;
  Request.Url    := Url;
  Request.Fields := Fields;
  FRequests.Add(Request);

  const HasResponse = (FResponses.Count > 0);
  if not HasResponse then
    raise EInvalidOpException.Create(NoCannedResponse);

  Result := FResponses.Dequeue;
end;

procedure TFakeUpstreamHttp.EnqueueResponse(const StatusCode: Integer; const Body: string);
begin
  var Response: TUpstreamHttpResponse;
  Response.StatusCode := StatusCode;
  Response.Body       := Body;
  FResponses.Enqueue(Response);
end;

function TFakeUpstreamHttp.LastRequest: TRecordedUpstreamRequest;
begin
  const HasRequest = (FRequests.Count > 0);
  if not HasRequest then
    raise EInvalidOpException.Create(NoRequestRecorded);

  Result := FRequests.Last;
end;

function TFakeUpstreamHttp.RequestCount: Integer;
begin
  Result := FRequests.Count;
end;

end.
