import React, { ReactNode, Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Box from '@mui/material/Box';
import type SvgIcon from '@mui/material/SvgIcon';
import CloudOffOutlined from '@mui/icons-material/CloudOffOutlined';
import ErrorOutlineOutlined from '@mui/icons-material/ErrorOutlineOutlined';
import HourglassEmptyOutlined from '@mui/icons-material/HourglassEmptyOutlined';
import HubOutlined from '@mui/icons-material/HubOutlined';
import LockOutlined from '@mui/icons-material/LockOutlined';
import PowerSettingsNewOutlined from '@mui/icons-material/PowerSettingsNewOutlined';
import SearchOffOutlined from '@mui/icons-material/SearchOffOutlined';
import ShieldOutlined from '@mui/icons-material/ShieldOutlined';
import SpeedOutlined from '@mui/icons-material/SpeedOutlined';
import VisibilityOffOutlined from '@mui/icons-material/VisibilityOffOutlined';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { InformationOutline } from 'mdi-material-ui';
import Card from '@common/card/Card';
import { ErrorBoundary } from '../../Error';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import { ThreatPulseConnectCta, ThreatPulsePreviewChip, ThreatPulseSettingsCta, useThreatPulseImpression } from './ThreatPulseUnlock';
import { ThreatPulseCardQuery } from './__generated__/ThreatPulseCardQuery.graphql';
import { ThreatPulseBelowThreshold, ThreatPulseFreshness, ThreatPulsePreviewSignal, ThreatPulsePublishedSignal } from './ThreatPulseCardSignal';
import ThreatPulseCardSkeleton from './ThreatPulseCardSkeleton';
import ThreatPulseNotice from './ThreatPulseNotice';
import { PULSE_UNAVAILABLE_MESSAGES } from './threatPulseUtils';

export const threatPulseCardQuery = graphql`
  query ThreatPulseCardQuery($id: ID!) {
    pulseEntity(id: $id) {
      id
      access
      readable
      unavailable_reason
      sector_bucket
      information {
        published
        preview
        prevalence
        platforms_bucket
        first_seen_network
        last_seen_network
        trend
        trend_series
        sector_trend
        sector_platforms_bucket
        community_uniqueness
        updated_at
      }
    }
  }
`;

interface ThreatPulseCardProps {
  entityId: string;
}

const ThreatPulseCardTitle = ({ preview = false }: { preview?: boolean }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      {t_i18n('Threat Pulse')}
      <Tooltip>
        <TooltipTrigger asChild>
          <span aria-label={t_i18n('About Threat Pulse')} style={{ display: 'inline-flex' }}>
            <InformationOutline fontSize="small" color="primary" />
          </span>
        </TooltipTrigger>
        <TooltipContent>
          {t_i18n('Community signal from the platforms contributing to Threat Pulse: keyed hashes and counts only, published when at least the anonymity threshold of platforms observed the same object.')}
        </TooltipContent>
      </Tooltip>
      {preview && <ThreatPulsePreviewChip />}
    </Box>
  );
};

// A state that carries data (the published signal, the preview, and the skeleton holding their place) fills its cell of
// the overview layout like the widget next to it, its footer on the bottom edge. A compact state (below the anonymity
// threshold, a one-line notice, the error) takes the height of its content instead of a tall, mostly empty panel.
const ThreatPulseCardFrame = ({ preview = false, compact = false, children }: { preview?: boolean; compact?: boolean; children: ReactNode }) => (
  <Box sx={compact ? undefined : { height: '100%' }} data-testid="threat-pulse-card-container">
    <Card
      title={<ThreatPulseCardTitle preview={preview} />}
      fullHeight={!compact}
      sx={compact ? undefined : { display: 'flex', flexDirection: 'column' }}
    >
      {children}
    </Card>
  </Box>
);

const ThreatPulseNoticeCard = (props: React.ComponentProps<typeof ThreatPulseNotice>) => (
  <ThreatPulseCardFrame compact>
    <ThreatPulseNotice {...props} />
  </ThreatPulseCardFrame>
);

// Not connected to XTM Hub: what Threat Pulse would add, and the one step to get it.
const ThreatPulseNotConnectedCard = () => {
  const { t_i18n } = useFormatter();
  useThreatPulseImpression('entity_card', true);
  return (
    <ThreatPulseNoticeCard
      icon={HubOutlined}
      testId="threat-pulse-not-connected"
      message={t_i18n('Connect the platform to XTM Hub to see how widespread this object is across the OpenCTI community and whether it is rising, without sending anything about it.')}
      action={<ThreatPulseConnectCta surface="entity_card" />}
    />
  );
};

type PulseEntity = ThreatPulseCardQuery['response']['pulseEntity'];

const ThreatPulsePreviewCard = ({ pulseEntity }: { pulseEntity: PulseEntity }) => {
  useThreatPulseImpression('entity_card', true);
  return (
    <ThreatPulseCardFrame preview>
      <ThreatPulsePreviewSignal information={pulseEntity.information?.preview ? pulseEntity.information : null} />
    </ThreatPulseCardFrame>
  );
};

const PULSE_REASON_ICONS: Record<string, typeof SvgIcon> = {
  not_enabled: PowerSettingsNewOutlined,
  not_registered: HubOutlined,
  contribution_required: LockOutlined,
  hub_unreachable: CloudOffOutlined,
  rate_limited: SpeedOutlined,
  enterprise_edition_required: LockOutlined,
  out_of_scope: VisibilityOffOutlined,
  excluded: ShieldOutlined,
};

// Without any community data for the object, the reason alone: the message about the last known information would not
// apply.
const PULSE_NO_DATA_MESSAGES: Record<string, string> = {
  hub_unreachable: 'XTM Hub could not be reached: the community data of this object appears once XTM Hub answers.',
};

const ThreatPulseCardComponent = ({ entityId }: ThreatPulseCardProps) => {
  const { t_i18n } = useFormatter();
  const { settings } = useAuth();
  const { pulseEntity } = useLazyLoadQuery<ThreatPulseCardQuery>(threatPulseCardQuery, { id: entityId }, { fetchPolicy: 'store-and-network' });
  const reason = pulseEntity.unavailable_reason;
  if (reason === 'out_of_scope') {
    return (
      <ThreatPulseNoticeCard
        icon={VisibilityOffOutlined}
        testId="threat-pulse-out-of-scope"
        message={t_i18n('Threat Pulse does not cover this entity type on this platform.')}
        action={<ThreatPulseSettingsCta />}
      />
    );
  }
  if (pulseEntity.access === 'not_connected') {
    // Only where XTM Hub can be reached: an isolated platform is never asked to connect.
    return settings?.xtm_hub_backend_is_reachable
      ? <ThreatPulseNotConnectedCard />
      : (
          <ThreatPulseNoticeCard
            icon={CloudOffOutlined}
            testId="threat-pulse-hub-unreachable"
            message={t_i18n('Threat Pulse needs a connection to XTM Hub, which this platform cannot reach.')}
          />
        );
  }
  if (pulseEntity.access === 'off') {
    return (
      <ThreatPulseNoticeCard
        icon={PowerSettingsNewOutlined}
        testId="threat-pulse-off"
        message={t_i18n('Threat Pulse is turned off on this platform.')}
        action={<ThreatPulseSettingsCta />}
      />
    );
  }
  if (pulseEntity.access === 'preview') {
    return <ThreatPulsePreviewCard pulseEntity={pulseEntity} />;
  }
  const { information } = pulseEntity;
  if (pulseEntity.access !== 'full' || (!information && reason)) {
    // Full experience, no community data for the object yet: why, instead of an empty or missing card.
    const message = (reason && (PULSE_NO_DATA_MESSAGES[reason] ?? PULSE_UNAVAILABLE_MESSAGES[reason])) ?? 'The community data of this object is not available yet.';
    return (
      <ThreatPulseNoticeCard
        icon={(reason && PULSE_REASON_ICONS[reason]) || HourglassEmptyOutlined}
        testId="threat-pulse-unavailable"
        message={t_i18n(message)}
      />
    );
  }
  if (!information) {
    return (
      <ThreatPulseNoticeCard
        icon={SearchOffOutlined}
        testId="threat-pulse-no-match"
        message={t_i18n('Threat Pulse cannot compare this object with other platforms: it has no name, identifier or supported pattern to match.')}
      />
    );
  }
  // With the last known information, the reason it may be stale (XTM Hub out of reach, rate limited) in the footer.
  const staleness = reason ? PULSE_UNAVAILABLE_MESSAGES[reason] : null;
  const footer = (
    <ThreatPulseFreshness
      updatedAt={information.updated_at}
      notice={staleness ? t_i18n(staleness) : null}
      noticeIcon={reason ? PULSE_REASON_ICONS[reason] : undefined}
    />
  );
  return (
    <ThreatPulseCardFrame compact={!information.published}>
      {information.published
        ? <ThreatPulsePublishedSignal information={information} sectorBucket={pulseEntity.sector_bucket} footer={footer} />
        : <ThreatPulseBelowThreshold information={information} footer={footer} />}
    </ThreatPulseCardFrame>
  );
};

// The request for the community data failed: the overview keeps the card, and says so in one line.
const ThreatPulseCardError = () => {
  const { t_i18n } = useFormatter();
  return (
    <ThreatPulseNoticeCard
      icon={ErrorOutlineOutlined}
      tone="error"
      testId="threat-pulse-error"
      message={t_i18n('The community data of this object could not be loaded. Reload the page to try again.')}
    />
  );
};

/**
 * Threat Pulse widget of an entity overview. Contributing, it leads with the signal itself - how many platforms
 * observed the object, its prevalence and trend - or says in a short card that the object is below the anonymity
 * threshold; in preview, the coarse signal of the digest and the step to the full experience; not connected, what it
 * would add and how to connect. Whatever the platform or the object, it renders a card - loading, Threat Pulse turned
 * off, the entity type left out of its scope, XTM Hub out of reach, nothing to match, a failed request - so that the
 * overview layout never shows a hole.
 */
const ThreatPulseCard = ({ entityId }: ThreatPulseCardProps) => (
  <ErrorBoundary display={ThreatPulseCardError}>
    <Suspense
      fallback={(
        <ThreatPulseCardFrame>
          <ThreatPulseCardSkeleton />
        </ThreatPulseCardFrame>
      )}
    >
      <ThreatPulseCardComponent entityId={entityId} />
    </Suspense>
  </ErrorBoundary>
);

export default ThreatPulseCard;
