import { AutoAwesomeOutlined, CloudDownloadOutlined, ExtensionOutlined, FileDownloadOutlined, InputOutlined, StreamOutlined, UploadFileOutlined } from '@mui/icons-material';
import type { SvgIconComponent } from '@mui/icons-material';

export type IngestionConnectorType
  = | 'INTERNAL_ENRICHMENT'
    | 'INTERNAL_INGESTION'
    | 'EXTERNAL_IMPORT'
    | 'INTERNAL_EXPORT_FILE'
    | 'INTERNAL_IMPORT_FILE'
    | 'STREAM';

const CONNECTOR_TYPE_ICONS: Record<IngestionConnectorType, SvgIconComponent> = {
  EXTERNAL_IMPORT: CloudDownloadOutlined,
  INTERNAL_ENRICHMENT: AutoAwesomeOutlined,
  INTERNAL_EXPORT_FILE: FileDownloadOutlined,
  INTERNAL_IMPORT_FILE: UploadFileOutlined,
  INTERNAL_INGESTION: InputOutlined,
  STREAM: StreamOutlined,
};

// Accepts any string on purpose: catalog data may carry connector types
// unknown to this build, which fall back to the generic extension icon.
export const getConnectorTypeIcon = (containerType: string): SvgIconComponent => {
  return CONNECTOR_TYPE_ICONS[containerType as IngestionConnectorType] ?? ExtensionOutlined;
};

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
