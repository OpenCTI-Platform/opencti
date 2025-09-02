export type IngestionConnectorType =
  | 'INTERNAL_ENRICHMENT'
  | 'EXTERNAL_IMPORT'
  | 'INTERNAL_EXPORT_FILE'
  | 'INTERNAL_IMPORT_FILE';

export const ingestionConnectorTypeMetadata: Record<
IngestionConnectorType,
{ label: string; color: 'primary' | 'secondary' | 'error' | 'success' }
> = {
  EXTERNAL_IMPORT: {
    label: 'External import',
    color: 'primary',
  },
  INTERNAL_ENRICHMENT: {
    label: 'Internal enrichment',
    color: 'secondary',
  },
  INTERNAL_EXPORT_FILE: {
    label: 'Internal export file',
    color: 'error',
  },
  INTERNAL_IMPORT_FILE: {
    label: 'Internal import file',
    color: 'success',
  },
};
