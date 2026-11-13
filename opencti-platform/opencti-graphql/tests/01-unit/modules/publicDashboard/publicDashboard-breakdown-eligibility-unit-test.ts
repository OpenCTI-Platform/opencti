/**
 * The public dashboards repeat two rules of the front on the server: whether a stored widget can be broken down, and the
 * types its dataset is restricted to. The front runs the same cases through its own copy
 * (opencti-front/src/utils/widget/widgetBreakdownEligibility.test.ts), read from the same file.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { canWidgetBreakDown, getBreakdownEntityTypes } from '../../../../src/modules/publicDashboard/publicDashboard-breakdown';
import { RELATION_TYPE_FILTER, TYPE_FILTER } from '../../../../src/utils/filtering/filtering-constants';

type EligibilityCase = { name: string; widget: any; canBreakDown: boolean; entityTypes: string[] };
const { cases } = JSON.parse(
  readFileSync(new URL('../../../data/widget-breakdown/breakdown-eligibility-cases.json', import.meta.url), 'utf8'),
) as { cases: EligibilityCase[] };

// Type filter key of the perspectives with a public breakdown, as buildPublicBreakdownArgs reads it: the logs of the
// audits widgets have none
const TYPE_FILTER_KEYS: Record<string, string> = { entities: TYPE_FILTER, relationships: RELATION_TYPE_FILTER };

describe('breakdown eligibility shared with the front', () => {
  it.each(cases)('should tell whether $name can be broken down, as the front does', ({ widget, canBreakDown }) => {
    expect(canWidgetBreakDown(widget)).toBe(canBreakDown);
  });

  it.each(cases.filter(({ widget }) => TYPE_FILTER_KEYS[widget.perspective]))('should read the types of $name as the front does', ({ widget, entityTypes }) => {
    expect(getBreakdownEntityTypes(widget.dataSelection[0]?.filters, TYPE_FILTER_KEYS[widget.perspective])).toEqual(entityTypes);
  });
});
