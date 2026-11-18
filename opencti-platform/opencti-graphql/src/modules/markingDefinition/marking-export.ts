import type { BasicStoreEntity } from '../../types/store';
import type { MarkingImportConfiguration } from './marking-import-schema';

export type BasicStoreEntityMarking = BasicStoreEntity & {
  definition_type: string;
  definition: string;
  x_opencti_color?: string;
  x_opencti_order?: number;
};

export const exportMarking = (marking: BasicStoreEntityMarking): MarkingImportConfiguration => ({
  definition_type: marking.definition_type,
  definition: marking.definition,
  x_opencti_color: marking.x_opencti_color ?? null,
  x_opencti_order: marking.x_opencti_order ?? 0,
});
