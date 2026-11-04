import { describe, expect, it } from 'vitest';
import { getCustomFieldWidgetColumn } from './customFieldWidgetColumn';

describe('getCustomFieldWidgetColumn', () => {
  it('keeps the registered column of a standard attribute', () => {
    expect(getCustomFieldWidgetColumn('created_at', 'Creation date')).toBeUndefined();
  });

  it('labels a custom field column, with its technical name as fallback', () => {
    expect(getCustomFieldWidgetColumn('x_opencti_cf_note', 'Note')?.label).toBe('Note');
    expect(getCustomFieldWidgetColumn('x_opencti_cf_note', null)?.label).toBe('x_opencti_cf_note');
  });

  it('renders the custom field value of the element', () => {
    const render = getCustomFieldWidgetColumn('x_opencti_cf_tags')?.render;
    const node = { customFieldValues: [{ field_id: 'tags', field_name: 'x_opencti_cf_tags', select_values: ['a', 'b'] }] };
    expect(render).toBeDefined();
    expect(render?.(node, {} as never)).toBeTruthy();
  });
});
