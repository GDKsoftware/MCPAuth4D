unit MCPAuth.Upstream.Http.Interfaces;

interface

uses
  Spring.Collections;

type
  TUpstreamHttpResponse = record
    StatusCode: Integer;
    Body: string;
  end;

  IUpstreamHttp = interface
    ['{7A61C3E8-0F2D-4B59-8E14-C6D93B2A5F70}']
    function PostForm(const Url: string; const Fields: TArray<TPair<string, string>>): TUpstreamHttpResponse;
  end;

implementation

end.
