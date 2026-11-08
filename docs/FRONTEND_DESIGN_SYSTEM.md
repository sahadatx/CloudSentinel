# Frontend design system

The console follows DroidShield's current dark workspace style. Its shared adapter
is `frontend/cloudsentinel-ui/src/droidshield-theme.css`, imported after the existing
page layouts. The application has no runtime dependency on DroidShield.

## Palette and hierarchy

| Purpose | Color |
| --- | --- |
| Canvas | `#0b1117` |
| Sidebar | `#0d151c` |
| Surface | `#111a22` |
| Border | `#202c36` |
| Primary text | `#e7edf2` |
| Secondary text | `#82919e` |
| Primary action | `#42d6c4`, with dark text |

Severity and workflow badges retain their own semantic colors. Table column
accents and row stripes support scanning; they do not indicate severity. Avoid
universal descendant color or background resets, which can erase these meanings.

## Shared components

- `DataTable` requires a descriptive caption and owns horizontal scrolling. Use
  column header scopes. Set `actions` only when the trailing column contains row
  actions; that column stays visible during horizontal scrolling.
- `ViewAction` provides the shared eye icon and View control. Keep permitted
  mutations in the existing action menus.
- `FilterField` supplies a visible field label. `FilterFooter` explains automatic
  updates and keeps Reset visible but disabled when no filters are active. Changes
  reset the related pagination offset.
- `Pagination` displays the current range, total and page, formats counts locally,
  and repairs an out-of-range offset when a result set shrinks.
- `RightDrawer` uses a native modal dialog for focus containment, accessible
  headings, Escape handling and focus return. It locks page scrolling while open.
- `Icon` and `KpiIcon` use local SVG paths. `RiskProgress` uses the backend's fixed
  risk bands; it does not recalculate risk scores.

Desktop drawer forms use two columns where fields permit, with long fields and
action rows spanning the form. Narrow screens use one column. Tables keep their
own horizontal scroll area without expanding the page.

Report, finding, remediation and compliance badges use semantic status classes;
both `status-pill completed` and `status-pill status-completed` are supported.
Disabled and read-only form controls have a separate muted surface. Saving forms
keep their busy state visible and guard against duplicate submissions.

Policy assessment lists use the API's total, offset and limit rather than stopping
at the first response. Each result filter resets its own page. Authentication,
recovery, header actions and navigation use the shared local SVG icons; narrow
login screens retain the product brand. Compliance and audit filters collapse to
one column, and report, remediation and compliance KPIs use two mobile columns.

The sign-in form has only email and password inputs. The API resolves a single
eligible organization membership without a workspace field. Normal session
expiry applies; the form does not request a remembered session.

## Data and checks

Counts, rows, permissions and supported actions remain API-backed. Empty, loading
and error states must stay distinct; do not invent records, trends or counters.

Run `npm run lint` and `npm run build` from
`frontend/cloudsentinel-ui` after changes. Verify populated lists, filter reset,
multiple pages, drawer keyboard behavior and narrow layouts when these shared
components change. Use an isolated synthetic dataset for visual checks.
