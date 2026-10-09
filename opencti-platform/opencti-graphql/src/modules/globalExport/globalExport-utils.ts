import { extractEntityRepresentativeName } from '../../database/entity-representative';
import type { BasicStoreBase } from '../../types/store';

export interface ExportReference {
  export_id?: string;
  standard_id: string;
  name: string;
}

export const toExportReference = (entity: BasicStoreBase & { export_id?: string }): ExportReference => ({
  ...(entity.export_id ? { export_id: entity.export_id } : {}),
  standard_id: entity.standard_id,
  name: extractEntityRepresentativeName(entity),
});
