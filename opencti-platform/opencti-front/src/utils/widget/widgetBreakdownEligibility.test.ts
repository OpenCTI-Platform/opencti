import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { Widget, WidgetPerspective } from './widget';
import { canWidgetBreakDown, getBreakdownEntityTypes } from './widgetBreakdown';

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
