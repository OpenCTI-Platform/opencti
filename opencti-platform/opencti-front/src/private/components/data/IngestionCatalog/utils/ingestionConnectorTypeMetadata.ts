export type IngestionConnectorType =
  | 'INTERNAL_ENRICHMENT'
  | 'INTERNAL_INGESTION'
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
        color: 'secondary' as const,
      };
    case 'INTERNAL_ENRICHMENT':
      return {
        label: t_i18n('Internal enrichment'),
        color: 'warning' as const,
      };
    case 'INTERNAL_EXPORT_FILE':
      return {
        label: t_i18n('Internal export file'),
        color: 'warning' as const,
      };
    case 'INTERNAL_IMPORT_FILE':
      return {
        label: t_i18n('Internal import file'),
        color: 'warning' as const,
      };
    case 'INTERNAL_INGESTION':
      return {
        label: t_i18n('Internal ingestion'),
        color: 'warning' as const,
      };
    case 'STREAM':
      return {
        label: t_i18n('Stream'),
        color: '#ff78ffff',
      };
    default:
      // return raw type if type not handled
      return {
        label: containerType,
        color: 'default' as const,
      };
  }
};
