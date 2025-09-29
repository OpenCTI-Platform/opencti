export type IngestionConnectorType =
  | 'INTERNAL_ENRICHMENT'
  | 'EXTERNAL_IMPORT'
  | 'INTERNAL_EXPORT_FILE'
  | 'INTERNAL_IMPORT_FILE'
  | 'STREAM';

export const getConnectorMetadata = (
  containerType: IngestionConnectorType,
  t_i18n: (key: string) => string,
) => {
  switch (containerType) {
    case 'EXTERNAL_IMPORT':
      return {
        label: t_i18n('External import'),
        color: 'primary' as const,
      };
    case 'INTERNAL_ENRICHMENT':
      return {
        label: t_i18n('Internal enrichment'),
        color: 'secondary' as const,
      };
    case 'INTERNAL_EXPORT_FILE':
      return {
        label: t_i18n('Internal export file'),
        color: 'error' as const,
      };
    case 'INTERNAL_IMPORT_FILE':
      return {
        label: t_i18n('Internal import file'),
        color: 'success' as const,
      };
    case 'STREAM':
      return {
        label: t_i18n('Stream'),
        color: 'primary' as const,
      };
    default:
      return {
        label: t_i18n('Unknown connector'),
        color: 'primary' as const,
      };
  }
};
