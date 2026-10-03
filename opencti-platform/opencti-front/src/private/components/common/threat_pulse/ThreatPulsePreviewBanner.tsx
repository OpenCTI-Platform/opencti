import React, { Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, useQueryLoader, usePreloadedQuery } from 'react-relay';
import { useNavigate } from 'react-router';
import TopBanner from '../../../../components/TopBanner';
import { useFormatter } from '../../../../components/i18n';
import { dispatch } from '../../../../utils/hooks/useBus';
import useAuth from '../../../../utils/hooks/useAuth';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from '../../../../utils/hooks/useGranted';
import { THREAT_PULSE_PREVIEW_BANNER_DISMISSED_BUS, THREAT_PULSE_PREVIEW_BANNER_VISIBLE_BUS, threatPulsePreviewBannerDismissKey } from '../../../../utils/bannerConstants';
import { THREAT_PULSE_SETTINGS_PATH, useThreatPulseImpression, useThreatPulseTelemetry } from './ThreatPulseUnlock';
import { ThreatPulsePreviewBannerQuery } from './__generated__/ThreatPulsePreviewBannerQuery.graphql';

const threatPulsePreviewBannerQuery = graphql`
  query ThreatPulsePreviewBannerQuery {
    pulseStatus {
      access
      preview_entities
    }
  }
`;

const ThreatPulsePreviewBannerContent = ({ queryRef, dismissKey }: { queryRef: PreloadedQuery<ThreatPulsePreviewBannerQuery>; dismissKey: string }) => {
  const { t_i18n, n } = useFormatter();
  const navigate = useNavigate();
  const isAdministrator = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const { trackCtaClick } = useThreatPulseTelemetry('banner');
  const { pulseStatus } = usePreloadedQuery(threatPulsePreviewBannerQuery, queryRef);
  const [dismissed] = useState(() => localStorage.getItem(dismissKey) === 'true');
  const isVisible = !dismissed && pulseStatus.access === 'preview' && pulseStatus.preview_entities > 0;
  useThreatPulseImpression('banner', isVisible);

  // The banner resolves its own visibility: useTopBanner keeps the shared top offset in sync through this bus.
  useEffect(() => {
    dispatch(THREAT_PULSE_PREVIEW_BANNER_VISIBLE_BUS, isVisible);
    return () => dispatch(THREAT_PULSE_PREVIEW_BANNER_VISIBLE_BUS, false);
  }, [isVisible]);

  if (!isVisible) return null;

  const bannerText = (
    <>
      <strong>{t_i18n('Threat Pulse preview is live:')}</strong>
      {` ${n(pulseStatus.preview_entities)} ${t_i18n('of your objects are seen across the community.')} `}
      {isAdministrator
        ? t_i18n('Contribute to unlock the full picture.')
        : t_i18n('Ask your administrator to enable the Threat Pulse contribution in Settings > Filigran Experience.')}
    </>
  );
  return (
    <TopBanner
      bannerColor="gradient_blue"
      bannerText={bannerText}
      buttonText={isAdministrator ? t_i18n('Unlock the full Threat Pulse') : undefined}
      onButtonClick={isAdministrator ? () => {
        trackCtaClick();
        navigate(THREAT_PULSE_SETTINGS_PATH);
      } : undefined}
      dismissible
      dismissKey={dismissKey}
      dismissBus={THREAT_PULSE_PREVIEW_BANNER_DISMISSED_BUS}
    />
  );
};

/**
 * One dismissable banner per user once the Threat Pulse preview matches objects of the platform: the count of local
 * objects found in the community digest and the one step to the full experience.
 */
const ThreatPulsePreviewBanner = () => {
  const { me } = useAuth();
  const dismissKey = threatPulsePreviewBannerDismissKey(me.id);
  const [queryRef, loadQuery] = useQueryLoader<ThreatPulsePreviewBannerQuery>(threatPulsePreviewBannerQuery);
  useEffect(() => {
    if (localStorage.getItem(dismissKey) !== 'true') {
      loadQuery({}, { fetchPolicy: 'store-and-network' });
    }
  }, [dismissKey]);
  if (!queryRef) return null;
  return (
    <Suspense fallback={null}>
      <ThreatPulsePreviewBannerContent queryRef={queryRef} dismissKey={dismissKey} />
    </Suspense>
  );
};

export default ThreatPulsePreviewBanner;
