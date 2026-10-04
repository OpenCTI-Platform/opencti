import React, { ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import { ThreatPulseUnlockAccessQuery } from './__generated__/ThreatPulseUnlockAccessQuery.graphql';
import { useNavigate } from 'react-router';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/styles';
import LockOutlined from '@mui/icons-material/LockOutlined';
import { Chip, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from '../../../../utils/hooks/useGranted';
import type { Theme } from '../../../../components/Theme';
import { ThreatPulseUnlockTelemetryMutation, PulseSurface } from './__generated__/ThreatPulseUnlockTelemetryMutation.graphql';

export const THREAT_PULSE_SETTINGS_PATH = '/dashboard/settings/experience';
export const XTM_HUB_CONNECT_PATH = '/redirect/connect-xtm-hub';

const threatPulseUnlockTelemetryMutation = graphql`
  mutation ThreatPulseUnlockTelemetryMutation($event: PulseTelemetryEvent!, $surface: PulseSurface!) {
    pulseTelemetry(event: $event, surface: $surface)
  }
`;

const threatPulseUnlockAccessQuery = graphql`
  query ThreatPulseUnlockAccessQuery {
    pulseStatus {
      access
    }
  }
`;

// The Threat Pulse access of the platform, without suspending the form that asks: null until known.
export const useThreatPulseAccess = () => {
  const [access, setAccess] = useState<ThreatPulseUnlockAccessQuery['response']['pulseStatus']['access'] | null>(null);
  useEffect(() => {
    const subscription = fetchQuery<ThreatPulseUnlockAccessQuery>(threatPulseUnlockAccessQuery, {}).subscribe({
      next: (data) => setAccess(data?.pulseStatus.access ?? null),
      error: () => setAccess(null),
    });
    return () => subscription.unsubscribe();
  }, []);
  return access;
};

// Usage telemetry of the preview surfaces: a failure never reaches the user.
export const useThreatPulseTelemetry = (surface: PulseSurface) => {
  const [commit] = useMutation<ThreatPulseUnlockTelemetryMutation>(threatPulseUnlockTelemetryMutation);
  const track = useCallback((event: 'impression' | 'cta_click') => {
    commit({ variables: { event, surface }, onError: () => undefined });
  }, [commit, surface]);
  return {
    trackImpression: useCallback(() => track('impression'), [track]),
    trackCtaClick: useCallback(() => track('cta_click'), [track]),
  };
};

// One impression per mount of a preview surface.
export const useThreatPulseImpression = (surface: PulseSurface, active: boolean) => {
  const { trackImpression } = useThreatPulseTelemetry(surface);
  const tracked = useRef(false);
  useEffect(() => {
    if (active && !tracked.current) {
      tracked.current = true;
      trackImpression();
    }
  }, [active, trackImpression]);
};

export const ThreatPulsePreviewChip = () => {
  const { t_i18n } = useFormatter();
  return <Chip label={t_i18n('Preview')} severity="info" data-testid="threat-pulse-preview-chip" />;
};

interface ThreatPulseLockedRowProps {
  label: string;
}

// A row of the full experience shown in the preview: it names what it would show, never a fake or blurred value.
export const ThreatPulseLockedRow = ({ label }: ThreatPulseLockedRowProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const secondary = { color: theme.palette.text.secondary };
  const availability = t_i18n('Available when your platform contributes');
  return (
    <Box
      data-testid="threat-pulse-locked-row"
      sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 2, minHeight: 32 }}
    >
      <Text variant="content-compact" style={secondary}>{label}</Text>
      <Box sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.5 }} aria-label={`${label}: ${availability}`}>
        <LockOutlined fontSize="small" color="disabled" />
        <Text variant="content-compact" style={secondary}>{availability}</Text>
      </Box>
    </Box>
  );
};

// The ranks of a ranking that contributing would name, folded into one row.
export const ThreatPulseLockedRanksRow = ({ count }: { count: number }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const label = t_i18n('{count, plural, one {# more trending object} other {# more trending objects}} - available when your platform contributes', { values: { count } });
  return (
    <Box data-testid="threat-pulse-locked-ranks" aria-label={label} sx={{ display: 'flex', alignItems: 'center', gap: 0.5, minHeight: 32 }}>
      <LockOutlined fontSize="small" color="disabled" />
      <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{label}</Text>
    </Box>
  );
};

interface ThreatPulseCtaProps {
  surface: PulseSurface;
}

const AskAdministrator = ({ children }: { children: ReactNode }) => {
  const theme = useTheme<Theme>();
  return (
    <Text variant="content-compact" style={{ color: theme.palette.text.secondary }} data-testid="threat-pulse-ask-administrator">
      {children}
    </Text>
  );
};

// The one step of a preview surface: administrators contribute, the others know whom to ask and where.
export const ThreatPulseUnlockCta = ({ surface }: ThreatPulseCtaProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const isAdministrator = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const { trackCtaClick } = useThreatPulseTelemetry(surface);
  if (!isAdministrator) {
    return <AskAdministrator>{t_i18n('Ask your administrator to turn on contribution in Settings > Filigran Experience.')}</AskAdministrator>;
  }
  return (
    <Button
      variant="secondary"
      onClick={() => {
        trackCtaClick();
        navigate(THREAT_PULSE_SETTINGS_PATH);
      }}
      data-testid="threat-pulse-unlock-cta"
    >
      {t_i18n('Set up contribution')}
    </Button>
  );
};

// The Threat Pulse settings, for the administrators who can change them: the others have nothing to act on.
export const ThreatPulseSettingsCta = () => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const isAdministrator = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  if (!isAdministrator) {
    return null;
  }
  return (
    <Button
      variant="secondary"
      onClick={() => navigate(THREAT_PULSE_SETTINGS_PATH)}
      data-testid="threat-pulse-settings-cta"
    >
      {t_i18n('Open Threat Pulse settings')}
    </Button>
  );
};

export const ThreatPulseConnectCta = ({ surface }: ThreatPulseCtaProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const isAdministrator = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const { trackCtaClick } = useThreatPulseTelemetry(surface);
  if (!isAdministrator) {
    return (
      <AskAdministrator>
        {t_i18n('Ask your administrator to connect the platform to XTM Hub in Settings > Filigran Experience.')}
      </AskAdministrator>
    );
  }
  return (
    <Button
      variant="secondary"
      onClick={() => {
        trackCtaClick();
        navigate(XTM_HUB_CONNECT_PATH);
      }}
      data-testid="threat-pulse-connect-cta"
    >
      {t_i18n('Connect to XTM Hub')}
    </Button>
  );
};

// Why the "Trending in my sector" trigger type cannot be chosen, and the one step to enable it.
export const ThreatPulseTriggerNotice = ({ access }: { access: string | null }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const locked = access === 'preview' || access === 'not_connected';
  useThreatPulseImpression('notifications', locked);
  if (!locked && access !== 'off') {
    return null;
  }
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }} data-testid="threat-pulse-trigger-notice">
      <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>
        {access === 'off'
          ? t_i18n('Trending in my sector (Threat Pulse) is unavailable: Threat Pulse is turned off on this platform.')
          : t_i18n('Trending in my sector (Threat Pulse) is part of the full Threat Pulse experience, unlocked by contributing.')}
      </Text>
      {access === 'preview' && <ThreatPulseUnlockCta surface="notifications" />}
      {access === 'not_connected' && <ThreatPulseConnectCta surface="notifications" />}
    </Box>
  );
};
