import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { Widget, WidgetPerspective } from './widget';
import { canWidgetBreakDown, getBreakdownEntityTypes } from './widgetBreakdown';
import { deserializeDashboardManifestForFrontend } from '../../components/dashboard/dashboard-utils';
import { toB64 } from '../String';

// Cases shared with the public dashboards, which repeat these rules on the server
// (opencti-graphql/tests/01-unit/modules/publicDashboard/publicDashboard-breakdown-eligibility-unit-test.ts),
// read as a file: it is outside the front TypeScript project.
type EligibilityCase = { name: string; widget: Widget; canBreakDown: boolean; entityTypes: string[] };
const { cases } = JSON.parse(readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), '../../../../opencti-graphql/tests/data/widget-breakdown/breakdown-eligibility-cases.json'),
  'utf8',
)) as { cases: EligibilityCase[] };

describe('breakdown eligibility shared with the public dashboards', () => {
  it.each(cases)('tells whether $name can be broken down, as the public dashboards do', ({ widget, canBreakDown }) => {
    expect(canWidgetBreakDown(widget)).toBe(canBreakDown);
  });

  it.each(cases)('reads the types of $name, as the public dashboards do', ({ widget, entityTypes }) => {
    // The perspective of the widget, none included: its type filter key
    expect(getBreakdownEntityTypes(widget.dataSelection[0]?.filters, widget.perspective as WidgetPerspective)).toEqual(entityTypes);
  });
});

// The dashboard page and the widget editor read the widget once the dashboard loader normalized its stored
// filters (keys as strings, ids added), not the stored widget itself: the same answers must come out of it.
// The public dashboard page reads the stored widget as it is, as the cases above do.
const loaded = (widget: Widget): Widget => {
  const { widgets } = deserializeDashboardManifestForFrontend(toB64(JSON.stringify({ widgets: { [widget.id ?? 'w']: widget }, config: {} })));
  return Object.values(widgets)[0] as unknown as Widget;
};

describe('breakdown eligibility of the widgets the dashboard loader normalized', () => {
  it.each(cases)('tells whether $name can be broken down once loaded', ({ widget, canBreakDown }) => {
    expect(canWidgetBreakDown(loaded(widget))).toBe(canBreakDown);
  });

  it.each(cases)('reads the types of $name once loaded', ({ widget, entityTypes }) => {
    const widgetOfPage = loaded(widget);
    expect(getBreakdownEntityTypes(widgetOfPage.dataSelection[0]?.filters, widgetOfPage.perspective as WidgetPerspective)).toEqual(entityTypes);
  });
});
