import { describe, expect, it } from 'vitest';
import type { Widget } from '../../utils/widget/widget';
import type { DashboardVariable } from './dashboard-types';
import { getWidgetVariableIds, getWidgetVariableNames } from './dashboardWidgetVariableUsage';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const filter = (variableId: string) => ({ key: 'objectLabel', operator: 'eq', mode: 'or', values: [`$var:${variableId}`] });
const group = (filters: unknown[], filterGroups: unknown[] = []) => ({ mode: 'and', filters, filterGroups });

const widget = {
  dataSelection: [
    {
      filters: group([], [group([filter(A)])]),
      dynamicFrom: group([filter(B)]),
      dynamicTo: null,
    },
    { filters: group([filter(A), { key: 'entity_type', operator: 'eq', mode: 'or', values: ['Report'] }]) },
  ],
} as unknown as Pick<Widget, 'dataSelection'>;

const sector: DashboardVariable = { id: A, name: 'Sector', type: 'text', restriction: { mode: 'none' }, defaultValue: null };

describe('getWidgetVariableIds', () => {
  it('collects the tokens of filters, dynamicFrom and dynamicTo, nested groups included, once each', () => {
    expect(getWidgetVariableIds(widget)).toEqual([A, B]);
  });

  it('returns nothing for a widget without token', () => {
    expect(getWidgetVariableIds({ dataSelection: [] })).toEqual([]);
    expect(getWidgetVariableIds({ dataSelection: [{ filters: group([{ key: 'entity_type', operator: 'eq', mode: 'or', values: ['Report'] }]) }] } as never)).toEqual([]);
  });
});

describe('getWidgetVariableNames', () => {
  it('names a deleted variable Deleted variable', () => {
    expect(getWidgetVariableNames(widget, [sector], (message) => message)).toEqual(['Sector', 'Deleted variable']);
  });
});
