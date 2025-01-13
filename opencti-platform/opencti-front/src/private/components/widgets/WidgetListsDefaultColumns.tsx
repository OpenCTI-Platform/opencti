import type { WidgetColumn } from '../../../utils/widget/widget';

// eslint-disable-next-line import/prefer-default-export
export const defaultColumns: Record<string, WidgetColumn[]> = {
  relationships: [
    { attribute: 'entity_type' },
    { attribute: 'relationship_type' },
    { attribute: 'from_entity_type' },
    { attribute: 'from_relationship_type' },
    { attribute: 'to_entity_type' },
    { attribute: 'to_relationship_type' },
    { attribute: 'start_time' },
    { attribute: 'stop_time' },
    { attribute: 'created_at' },
    { attribute: 'createdBy' },
    { attribute: 'objectMarking' },
  ],
};
