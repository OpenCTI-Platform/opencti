import React, { FunctionComponent } from 'react';
import { DownloadOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import { Spinner, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { APP_BASE_PATH } from '../../../../../relay/environment';
import ConfigPresetResultGroups, { useResultLabel } from './ConfigPresetResultGroups';
import ConfigPresetResultLine, { CODE_UNCHANGED } from './ConfigPresetResultLine';
import type { ConfigPresetImportSession } from './ConfigPresetImportWizard';

interface ConfigPresetImportProgressProps {
  session: ConfigPresetImportSession | null;
}

// The import of the user runs: the results of the items so far, from the session
export const ConfigPresetImportProgress: FunctionComponent<ConfigPresetImportProgressProps> = ({ session }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const resultLabel = useResultLabel();
  const results = session?.results ?? [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
      <Spinner label={t_i18n('Import in progress')} />
      {session && session.total > 0 && (
        <Text variant="content-base">{t_i18n('{processed} of {total} items processed', { values: { processed: results.length, total: session.total } })}</Text>
      )}
      {results.map((result) => (
        <ConfigPresetResultLine key={`${result.type}/${result.key}`} label={resultLabel(result)} status={result.status} reason={result.reason} code={result.code} />
      ))}
    </div>
  );
};

interface ConfigPresetImportResultProps {
  session: ConfigPresetImportSession;
  // Clears the session and closes the wizard
  onClose: () => void;
}

// The items the platform already had as they are are counted apart: the backend counts them as skipped, which reads as if they were ignored
const toSummaryCounts = (session: ConfigPresetImportSession) => {
  const { counts, results } = session;
  if (!counts) {
    return null;
  }
  const unchanged = Math.min(counts.skipped, results.filter((result) => result.status === 'SKIPPED' && result.code === CODE_UNCHANGED).length);
  return { ...counts, skipped: counts.skipped - unchanged, unchanged };
};

// The result of the last import: the items grouped like the selection, and the report to download
export const ConfigPresetImportResult: FunctionComponent<ConfigPresetImportResultProps> = ({ session, onClose }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const counts = toSummaryCounts(session);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
      <Text variant="title-sm">{t_i18n('Import finished')}</Text>
      {counts && (
        <Text variant="content-base">
          {t_i18n('{created} created, {overwritten} overwritten, {unchanged} up to date, {skipped} skipped, {failed} failed', { values: counts })}
        </Text>
      )}
      <ConfigPresetResultGroups results={session.results} />
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1) }}>
        {session.report_id && (
          <Button
            variant="secondary"
            component="a"
            href={`${APP_BASE_PATH}/storage/get/${encodeURIComponent(session.report_id)}`}
            startIcon={<DownloadOutlined />}
          >
            {t_i18n('Download report')}
          </Button>
        )}
        <Button onClick={onClose}>{t_i18n('Close')}</Button>
      </div>
    </div>
  );
};
