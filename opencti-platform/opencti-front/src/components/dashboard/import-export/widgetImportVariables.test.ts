import { describe, expect, it } from 'vitest';
import { toB64 } from '../../../utils/String';
import { countMissingWidgetVariables } from './widgetImportVariables';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';

const group = (values: string[], filterGroups: unknown[] = []) => ({
  mode: 'and',
  filters: [{ key: ['entity_type'], values, operator: 'eq', mode: 'or' }],
  filterGroups,
});
const widgetFile = (selection: Record<string, unknown>) => JSON.stringify({
  openCTI_version: '7.0.0',
  type: 'widget',
  configuration: toB64(JSON.stringify({ type: 'number', perspective: 'entities', dataSelection: [selection] })),
});

describe('countMissingWidgetVariables', () => {
  it('should count the distinct variables missing from the dashboard', () => {
    const file = widgetFile({ filters: group([`$var:${A}`, `$var:${A}`, `$var:${B}`, `$var:${C}`]) });
    expect(countMissingWidgetVariables(file, new Set([B]))).toEqual(2);
  });

  it('should look into dynamicFrom, dynamicTo and nested groups', () => {
    const file = widgetFile({
      filters: group([], [group([`$var:${A}`])]),
      dynamicFrom: group([`$var:${B}`]),
      dynamicTo: group([`$var:${C}`]),
    });
    expect(countMissingWidgetVariables(file, new Set())).toEqual(3);
  });

  it('should return 0 for a widget without token or an unreadable file', () => {
    expect(countMissingWidgetVariables(widgetFile({ filters: group(['Malware']) }), new Set())).toEqual(0);
    expect(countMissingWidgetVariables('not a widget export', new Set())).toEqual(0);
  });
});
