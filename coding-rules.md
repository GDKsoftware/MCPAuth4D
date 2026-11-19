# Coding rules

The code follows the usual Delphi conventions of this repository: unit names `MCPAuth.Module.Process[.Implementation]`, one class per unit, Spring4D collections, no `initialization` sections, and zero compiler hints and warnings. This file lists the deliberate exceptions.

## Exceptions

- **One class per unit.** `MCPAuth.Web.Page.Models` holds all page models (`TPageModel` and the models and rows of every page). Together they are the contract between the controllers and the templates, and they only carry data.
- **No `System.Generics.Collections`.** `MCPAuth.Resource.Registry.Json` lists `System.Generics.Collections` in its `uses` clause only so that the inline function `TJSONArray.GetValue` of `System.JSON` is expanded (hint H2443 otherwise). It uses no type from that unit.
