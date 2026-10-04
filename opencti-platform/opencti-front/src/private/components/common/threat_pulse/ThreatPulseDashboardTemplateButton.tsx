import React, { createContext, ReactNode, Suspense, useCallback, useContext, useState } from 'react';
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
import { MESSAGING$ } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import { ThreatPulseDashboardTemplateButtonQuery } from './__generated__/ThreatPulseDashboardTemplateButtonQuery.graphql';
import { ThreatPulseDashboardTemplateButtonMutation } from './__generated__/ThreatPulseDashboardTemplateButtonMutation.graphql';
import { buildSectorBenchmarkDashboard, lockedSectorBenchmarkWidgets } from './threatPulseDashboardTemplate';
import { ThreatPulseLockedRow } from './ThreatPulseUnlock';

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

const useTemplateAccess = () => {
  const { pulseStatus } = useLazyLoadQuery<ThreatPulseDashboardTemplateButtonQuery>(threatPulseDashboardTemplateButtonQuery, {}, { fetchPolicy: 'store-and-network' });
  return pulseStatus.access === 'preview' || pulseStatus.access === 'full' ? pulseStatus.access : null;
};

const ThreatPulseDashboardTemplateDialog = ({ open, onClose }: { open: boolean; onClose: () => void }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const access = useTemplateAccess();
  const [commit, creating] = useApiMutation<ThreatPulseDashboardTemplateButtonMutation>(threatPulseDashboardTemplateButtonMutation);
  if (!access) {
    return null;
  }
  const preview = access === 'preview';
  const manifest = buildSectorBenchmarkDashboard(t_i18n, { preview });
  const widgetTitles = Object.values(manifest.widgets).map((widget) => widget.parameters?.title ?? '');
  const lockedTitles = preview ? lockedSectorBenchmarkWidgets(t_i18n) : [];
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
      onCompleted: (response, errors) => {
        const dashboardId = response?.workspaceDuplicate?.id;
        if ((errors && errors.length > 0) || !dashboardId) {
          MESSAGING$.notifyError(t_i18n('The dashboard could not be created from the template. Try again later.'));
          return;
        }
        onClose();
        navigate(`${resolveLink('Dashboard')}/${dashboardId}`);
      },
    });
  };
  return (
    <Dialog open={open} onClose={onClose} title={t_i18n('Dashboard template')} size="medium">
      <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }} data-testid="threat-pulse-template-card">
        <Thumbnail><ScaleBalance /></Thumbnail>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, minWidth: 0 }}>
          <Text variant="title-sm">{t_i18n('Sector benchmark')}</Text>
          <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{purpose}</Text>
          <Text variant="content-compact-bold">
            {t_i18n('{count, plural, one {# widget} other {# widgets}}', { values: { count: widgetTitles.length } })}
          </Text>
          <Box component="ul" sx={{ margin: 0, paddingLeft: 2.5, display: 'flex', flexDirection: 'column', gap: 0.25 }} data-testid="threat-pulse-template-widgets">
            {widgetTitles.map((title) => <li key={title}><Text variant="content-compact">{title}</Text></li>)}
          </Box>
          {lockedTitles.length > 0 && (
            <Box data-testid="threat-pulse-template-locked">
              {lockedTitles.map((title) => <ThreatPulseLockedRow key={title} label={title} />)}
            </Box>
          )}
          {preview && (
            <Text variant="content-compact" style={{ color: theme.palette.text.secondary }} data-testid="threat-pulse-template-preview-note">
              {t_i18n('In preview, the sector benchmark names what it would show, and the widgets of the full experience are added by a dashboard created once this platform contributes.')}
            </Text>
          )}
        </Box>
      </Box>
      <DialogActions>
        <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
        <Button onClick={create} disabled={creating} data-testid="threat-pulse-template-create">
          {t_i18n('Create a dashboard from this template')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

const ThreatPulseDashboardTemplateContext = createContext<(() => void) | null>(null);

/**
 * Holds the "Sector benchmark" template dialog and whether it is open, above the header that renders the button: the
 * header of the dashboards list mounts its buttons again whenever the list renders, which must not close the dialog.
 */
export const ThreatPulseDashboardTemplateProvider = ({ children }: { children: ReactNode }) => {
  const [open, setOpen] = useState(false);
  const openTemplate = useCallback(() => setOpen(true), []);
  const closeTemplate = useCallback(() => setOpen(false), []);
  return (
    <ThreatPulseDashboardTemplateContext.Provider value={openTemplate}>
      {children}
      <Suspense fallback={null}>
        <ThreatPulseDashboardTemplateDialog open={open} onClose={closeTemplate} />
      </Suspense>
    </ThreatPulseDashboardTemplateContext.Provider>
  );
};

const ThreatPulseDashboardTemplateButtonComponent = () => {
  const { t_i18n } = useFormatter();
  const openTemplate = useContext(ThreatPulseDashboardTemplateContext);
  const access = useTemplateAccess();
  if (!openTemplate || !access) {
    return null;
  }
  return (
    <Button
      variant="secondary"
      onClick={openTemplate}
      startIcon={<ScaleBalance fontSize="small" />}
      data-testid="threat-pulse-dashboard-template"
    >
      {t_i18n('Sector benchmark template')}
    </Button>
  );
};

// The "Sector benchmark" template, offered in preview too: its tiles then name what contributing unlocks. Rendered
// under a ThreatPulseDashboardTemplateProvider, which holds the dialog.
const ThreatPulseDashboardTemplateButton = () => (
  <Suspense fallback={null}>
    <ThreatPulseDashboardTemplateButtonComponent />
  </Suspense>
);

export default ThreatPulseDashboardTemplateButton;
