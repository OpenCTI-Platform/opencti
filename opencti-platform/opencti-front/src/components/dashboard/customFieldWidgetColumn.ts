import { DataTableColumn } from '../dataGrid/dataTableTypes';
import { defaultRender } from '../dataGrid/dataTableUtils';
import { getCustomFieldRawValueByFieldName, isCustomFieldAttribute } from '../../utils/customFields';

// Custom fields are not part of the DataTable column registry (they are dynamic, per-deployment),
// so a list widget column on a custom field needs its own label and a generic renderer reading
// the element's `customFieldValues` instead of relying on a registered one.
export const getCustomFieldWidgetColumn = (attribute: string, label?: string | null): Partial<DataTableColumn> | undefined => {
  if (!isCustomFieldAttribute(attribute)) return undefined;
  return {
    label: label || attribute,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    render: (node: any) => {
      const value = getCustomFieldRawValueByFieldName(node?.customFieldValues, attribute);
      return defaultRender(Array.isArray(value) ? value.join(', ') : value);
    },
  };
};
