import React, { useContext } from 'react';
import ToggleButton from '@mui/material/ToggleButton/ToggleButton';
import { HubOutlined } from '@mui/icons-material';
import IngestionCsvImport from '@components/data/ingestionCsv/IngestionCsvImport';
import IngestionTaxiiImport from '@components/data/ingestionTaxii/IngestionTaxiiImport';
import IngestionRssImport from '@components/data/IngestionRssImport';
import SyncImport from '@components/data/SyncImport';
import { IngestionRssLinesDataTableQuery$variables } from '@components/data/ingestionRss/__generated__/IngestionRssLinesDataTableQuery.graphql';
import { BuiltInIntegrationKind } from '@components/integrations/available/builtInIntegrations';
import { useFormatter } from '../../../../components/i18n';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { isNotEmptyField } from '../../../../utils/utils';

// The built-in methods whose configuration can be imported from a JSON file
// (matching the backend ...AddInputFromImport queries).
const IMPORTABLE_BUILT_IN_KINDS = ['sync', 'taxii', 'rss', 'csv'] as const;

export type ImportableBuiltInKind = (typeof IMPORTABLE_BUILT_IN_KINDS)[number];

export const isImportableBuiltInKind = (kind: string): kind is ImportableBuiltInKind => {
  return (IMPORTABLE_BUILT_IN_KINDS as readonly string[]).includes(kind);
};

// XTM Hub integration types of the importable built-in methods, used by the
// Hub redirect entry point (same values as the legacy feed screens).
const HUB_INTEGRATION_TYPES: Record<ImportableBuiltInKind, string> = {
  sync: 'stream',
  taxii: 'taxii_feed',
  rss: 'rss_feed',
  csv: 'csv_feed',
};

interface BuiltInIntegrationImportProps {
  kind: BuiltInIntegrationKind;
  hideTrigger?: boolean;
  onClose?: () => void;
}

// Configuration import (JSON file upload, or XTM Hub deep link download) for a
// built-in ingestion method: reuses the per-kind import components, which open
// the matching creation drawer prefilled with the parsed configuration.
export const BuiltInIntegrationImport = ({ kind, hideTrigger, onClose }: BuiltInIntegrationImportProps) => {
  switch (kind) {
    case 'sync':
      return <SyncImport paginationOptions={{}} hideTrigger={hideTrigger} onClose={onClose} />;
    case 'taxii':
      return <IngestionTaxiiImport paginationOptions={{}} hideTrigger={hideTrigger} onClose={onClose} />;
    case 'rss':
      return (
        <IngestionRssImport
          paginationOptions={{ count: 25 } as IngestionRssLinesDataTableQuery$variables}
          hideTrigger={hideTrigger}
          onClose={onClose}
        />
      );
    case 'csv':
      return <IngestionCsvImport hideTrigger={hideTrigger} onClose={onClose} />;
    default:
      return null;
  }
};

interface BuiltInIntegrationHubButtonProps {
  kind: BuiltInIntegrationKind;
}

// Entry point to import a configuration from the XTM Hub (redirects to the
// Hub, which deep-links back into the platform with the selected file).
export const BuiltInIntegrationHubButton = ({ kind }: BuiltInIntegrationHubButtonProps) => {
  const { t_i18n } = useFormatter();
  const { settings, isXTMHubAccessible } = useContext(UserContext);
  if (!isImportableBuiltInKind(kind)) return null;
  if (!isXTMHubAccessible || !isNotEmptyField(settings?.platform_xtmhub_url)) return null;
  const href = `${settings.platform_xtmhub_url}/redirect/opencti_integrations?platform_id=${settings.id}&integrationType=${HUB_INTEGRATION_TYPES[kind]}`;
  return (
    <ToggleButton
      value="import-hub"
      size="small"
      sx={{ marginLeft: 1 }}
      title={t_i18n('Import from Hub')}
      onClick={() => window.open(href, '_blank', 'noopener,noreferrer')}
    >
      <HubOutlined fontSize="small" color="primary" />
    </ToggleButton>
  );
};

export default BuiltInIntegrationImport;
