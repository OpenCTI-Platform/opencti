import React, { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useNavigate } from 'react-router';
import Box from '@mui/material/Box';
import DialogActions from '@mui/material/DialogActions';
import { useTheme } from '@mui/styles';
import { ScaleBalance } from 'mdi-material-ui';
import { Text, Thumbnail } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { serializeDashboardManifestForBackend } from '../../../../components/dashboard/dashboard-utils';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { resolveLink } from '../../../../utils/Entity';
import { ThreatPulseDashboardTemplateButtonQuery } from './__generated__/ThreatPulseDashboardTemplateButtonQuery.graphql';
import { ThreatPulseDashboardTemplateButtonMutation } from './__generated__/ThreatPulseDashboardTemplateButtonMutation.graphql';
import { buildSectorBenchmarkDashboard } from './threatPulseDashboardTemplate';

const threatPulseDashboardTemplateButtonQuery = graphql`
  query ThreatPulseDashboardTemplateButtonQuery {
    pulseStatus {
      id
      access
    }
  }
`;

const threatPulseDashboardTemplateButtonMutation = graphql`
  mutation ThreatPulseDashboardTemplateButtonMutation($input: WorkspaceDuplicateInput!) {
    workspaceDuplicate(input: $input) {
      id
    }
  }
`;

const ThreatPulseDashboardTemplateButtonComponent = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const { pulseStatus } = useLazyLoadQuery<ThreatPulseDashboardTemplateButtonQuery>(threatPulseDashboardTemplateButtonQuery, {}, { fetchPolicy: 'store-and-network' });
  const [commit, creating] = useApiMutation<ThreatPulseDashboardTemplateButtonMutation>(threatPulseDashboardTemplateButtonMutation);
  if (pulseStatus.access !== 'preview' && pulseStatus.access !== 'full') {
    return null;
  }
  const manifest = buildSectorBenchmarkDashboard(t_i18n);
  const widgetTitles = Object.values(manifest.widgets).map((widget) => widget.parameters?.title ?? '');
  const purpose = t_i18n('What rises in your sector and how this platform compares with the sector median, from Threat Pulse.');
  const create = () => {
    commit({
      variables: {
        input: {
          type: 'dashboard',
          name: t_i18n('Sector benchmark'),
          description: purpose,
          manifest: serializeDashboardManifestForBackend(manifest),
        },
      },
      onCompleted: (response) => {
        if (response.workspaceDuplicate?.id) {
          setOpen(false);
          navigate(`${resolveLink('Dashboard')}/${response.workspaceDuplicate.id}`);
        }
      },
    });
  };
  return (
    <>
      <Button
        variant="secondary"
        onClick={() => setOpen(true)}
        startIcon={<ScaleBalance fontSize="small" />}
        data-testid="threat-pulse-dashboard-template"
      >
        {t_i18n('Sector benchmark template')}
      </Button>
      <Dialog open={open} onClose={() => setOpen(false)} title={t_i18n('Dashboard template')} size="medium">
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }} data-testid="threat-pulse-template-card">
          <Thumbnail elevation={2}><ScaleBalance /></Thumbnail>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, minWidth: 0 }}>
            <Text variant="title-sm">{t_i18n('Sector benchmark')}</Text>
            <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{purpose}</Text>
            <Text variant="content-compact-bold">
              {t_i18n('{count, plural, one {# widget} other {# widgets}}', { values: { count: widgetTitles.length } })}
            </Text>
            <Box component="ul" sx={{ margin: 0, paddingLeft: 2.5, display: 'flex', flexDirection: 'column', gap: 0.25 }} data-testid="threat-pulse-template-widgets">
              {widgetTitles.map((title) => <li key={title}><Text variant="content-compact">{title}</Text></li>)}
            </Box>
            {pulseStatus.access === 'preview' && (
              <Text variant="content-compact" style={{ color: theme.palette.text.secondary }} data-testid="threat-pulse-template-preview-note">
                {t_i18n('In preview, the sector benchmark and the sector trends name what they would show once this platform contributes.')}
              </Text>
            )}
          </Box>
        </Box>
        <DialogActions>
          <Button variant="secondary" onClick={() => setOpen(false)}>{t_i18n('Cancel')}</Button>
          <Button onClick={create} disabled={creating} data-testid="threat-pulse-template-create">
            {t_i18n('Create a dashboard from this template')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

// The "Sector benchmark" template, offered in preview too: its tiles then name what contributing unlocks.
const ThreatPulseDashboardTemplateButton = () => (
  <Suspense fallback={null}>
    <ThreatPulseDashboardTemplateButtonComponent />
  </Suspense>
);

export default ThreatPulseDashboardTemplateButton;
