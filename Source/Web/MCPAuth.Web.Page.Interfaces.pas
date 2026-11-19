unit MCPAuth.Web.Page.Interfaces;

interface

type
  IPageRenderer = interface
    ['{5A0C3E52-8B1D-4C7A-9E64-2D1F7B6A4C10}']
    function Render(const Template: string; const Model: TObject): string;
  end;

implementation

end.
