unit MCPAuth.Upstream.Http;

interface

uses
  System.Classes,
  Spring.Collections,
  MCPAuth.Upstream.Http.Interfaces;

type
  TUpstreamHttp = class(TInterfacedObject, IUpstreamHttp)
  private
    function Send(const Url: string; const Source: TStream): TUpstreamHttpResponse;

  public
    function PostForm(const Url: string; const Fields: TArray<TPair<string, string>>): TUpstreamHttpResponse;
  end;

implementation

uses
  System.SysUtils,
  System.Net.URLClient,
  System.Net.HttpClient,
  MCPAuth.Upstream.FormEncoding,
  MCPAuth.Upstream.Exceptions;

const
  ConnectionTimeoutMilliseconds = 15000;
  ResponseTimeoutMilliseconds = 30000;
  FormContentType = 'application/x-www-form-urlencoded';
  JsonContentType = 'application/json';

resourcestring
  UpstreamUnreachable = 'The upstream endpoint %s could not be reached: %s';

{ TUpstreamHttp }

function TUpstreamHttp.PostForm(const Url: string; const Fields: TArray<TPair<string, string>>): TUpstreamHttpResponse;
begin
  const Body = TFormEncoding.Encode(Fields);
  const Source = TStringStream.Create(Body, TEncoding.UTF8);
  try
    Result := Send(Url, Source);
  finally
    Source.Free;
  end;
end;

function TUpstreamHttp.Send(const Url: string; const Source: TStream): TUpstreamHttpResponse;
begin
  const Client = THTTPClient.Create;
  try
    Client.ConnectionTimeout := ConnectionTimeoutMilliseconds;
    Client.ResponseTimeout   := ResponseTimeoutMilliseconds;
    Client.ContentType       := FormContentType;
    Client.Accept            := JsonContentType;

    try
      const Response = Client.Post(Url, Source);
      Result.StatusCode := Response.StatusCode;
      Result.Body       := Response.ContentAsString(TEncoding.UTF8);
    except
      // The message of a network error names the host, never the form fields.
      on E: ENetException do
        raise EUpstreamError.CreateFmt(UpstreamUnreachable, [Url, E.Message]);
    end;
  finally
    Client.Free;
  end;
end;

end.
