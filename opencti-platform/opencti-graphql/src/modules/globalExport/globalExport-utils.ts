import { extractEntityRepresentativeName } from '../../database/entity-representative';
import type { BasicStoreBase } from '../../types/store';

export interface ExportReference {
  export_id?: string;
  standard_id: string;
  name: string;
}

// A field whose name suggests a credential (header, query attribute, connector parameter) is never exported
// with its value, even when nothing else marks it as secret: it must be set again at import time.
export const SENSITIVE_FIELD_NAME = /authorization|token|key|secret|password|cookie|credential/i;

export const toExportReference = (entity: BasicStoreBase & { export_id?: string }): ExportReference => ({
  ...(entity.export_id ? { export_id: entity.export_id } : {}),
  standard_id: entity.standard_id,
  name: extractEntityRepresentativeName(entity),
});
