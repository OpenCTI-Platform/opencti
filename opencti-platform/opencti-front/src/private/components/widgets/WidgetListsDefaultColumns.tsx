import type { WidgetColumn } from '../../../utils/widget/widget';

export const commonWidgetColumns: Record<string, WidgetColumn[]> = {
  relationships: [
    { attribute: 'entity_type' },
    { attribute: 'relationship_type' },
    { attribute: 'from_entity_type', label: 'From entity type' },
    { attribute: 'from_relationship_type', label: 'From relationship type' },
    { attribute: 'to_entity_type', label: 'To entity type' },
    { attribute: 'to_relationship_type', label: 'To relationship type' },
    { attribute: 'start_time' },
    { attribute: 'stop_time' },
    { attribute: 'created_at' },
    { attribute: 'createdBy' },
    { attribute: 'objectMarking' },
  ],
};

export const defaultWidgetColumns: Record<string, WidgetColumn[]> = {
  relationships: [
    { attribute: 'entity_type' },
    { attribute: 'relationship_type' },
    { attribute: 'from_entity_type', label: 'From entity type' },
    { attribute: 'from_relationship_type', label: 'From relationship type' },
    { attribute: 'to_entity_type', label: 'To entity type' },
    { attribute: 'to_relationship_type', label: 'To relationship type' },
    { attribute: 'created_at' },
    { attribute: 'createdBy' },
    { attribute: 'objectMarking' },
  ],
};
