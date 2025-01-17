import type { WidgetColumn } from '../../../utils/widget/widget';

export const defaultWidgetColumns: Record<string, WidgetColumn[]> = {
  relationships: [
    { attribute: 'entity_type', label: 'Type' },
    { attribute: 'from_entity_type', label: 'Source type' },
    { attribute: 'from_relationship_type', label: 'Source name' },
    { attribute: 'to_entity_type', label: 'Target type' },
    { attribute: 'to_relationship_type', label: 'Target name' },
    { attribute: 'created_at', label: 'Platform creation date' },
    { attribute: 'createdBy' },
    { attribute: 'objectMarking' },
  ],
};

export const commonWidgetColumns: Record<string, WidgetColumn[]> = {
  relationships: [
    ...defaultWidgetColumns.relationships,
    { attribute: 'start_time' },
    { attribute: 'stop_time' },
  ],
};
