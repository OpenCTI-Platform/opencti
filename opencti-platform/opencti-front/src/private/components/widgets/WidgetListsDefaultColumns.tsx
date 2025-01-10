import type { WidgetColumn } from '../../../utils/widget/widget';

// eslint-disable-next-line import/prefer-default-export
export const defaultColumns: Record<string, WidgetColumn[]> = {
  relationships: [
    { attribute: 'entity_type' },
    { attribute: 'relationship_type' },
    { attribute: 'from.entity_type' },
    { attribute: 'from.relationship_type' },
    { attribute: 'to.entity_type' },
    { attribute: 'to.relationship_type' },
    { attribute: 'created_at' },
    { attribute: 'createdBy.name' },
    { attribute: 'objectMarking' },
  ],
};
