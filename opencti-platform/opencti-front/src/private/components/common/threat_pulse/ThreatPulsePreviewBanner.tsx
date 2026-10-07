import React, { Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, useQueryLoader, usePreloadedQuery } from 'react-relay';
import { useNavigate } from 'react-router';
import TopBanner from '../../../../components/TopBanner';
import { useFormatter } from '../../../../components/i18n';
import useBus from '../../../../utils/hooks/useBus';
import useAuth from '../../../../utils/hooks/useAuth';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from '../../../../utils/hooks/useGranted';
import { THREAT_PULSE_PREVIEW_BANNER_DISMISSED_BUS, threatPulsePreviewBannerDismissKey } from '../../../../utils/bannerConstants';
import { reportThreatPulsePreviewBannerVisible } from '../../../../utils/bannerUtils';
import { THREAT_PULSE_SETTINGS_PATH, useThreatPulseImpression, useThreatPulseTelemetry } from './ThreatPulseUnlock';
import { ThreatPulsePreviewBannerQuery } from './__generated__/ThreatPulsePreviewBannerQuery.graphql';

const threatPulsePreviewBannerQuery = graphql`
  query ThreatPulsePreviewBannerQuery {
    pulseStatus {
      access
      preview_entities
      preview_since
    }
  }
`;

const PREVIEW_BANNER_WINDOW_MS = 24 * 60 * 60 * 1000;

// The banner announces the preview: it shows during the first day the preview matches objects of the platform.
export const isPreviewBannerWindowOpen = (previewSince: string | null | undefined, now = Date.now()) => {
  const since = previewSince ? Date.parse(previewSince) : Number.NaN;
  return !Number.isNaN(since) && now - since < PREVIEW_BANNER_WINDOW_MS;
};

const ThreatPulsePreviewBannerContent = ({ queryRef, dismissKey }: { queryRef: PreloadedQuery<ThreatPulsePreviewBannerQuery>; dismissKey: string }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const isAdministrator = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const { trackCtaClick } = useThreatPulseTelemetry('banner');
  const { pulseStatus } = usePreloadedQuery(threatPulsePreviewBannerQuery, queryRef);
  const [dismissed, setDismissed] = useState(() => localStorage.getItem(dismissKey) === 'true');
  useBus(THREAT_PULSE_PREVIEW_BANNER_DISMISSED_BUS, (value: boolean) => {
    if (value) setDismissed(true);
  }, []);
  const [now, setNow] = useState(() => Date.now());
  const windowOpen = isPreviewBannerWindowOpen(pulseStatus.preview_since, now);
  // The window closes while the page stays open: the banner hides at its end, not at the next unrelated render.
  useEffect(() => {
    if (!windowOpen) return undefined;
    const remaining = Date.parse(pulseStatus.preview_since as string) + PREVIEW_BANNER_WINDOW_MS - Date.now();
    const timer = setTimeout(() => setNow(Date.now()), Math.min(Math.max(0, remaining), PREVIEW_BANNER_WINDOW_MS));
    return () => clearTimeout(timer);
  }, [windowOpen, pulseStatus.preview_since]);
  const isVisible = !dismissed
    && pulseStatus.access === 'preview'
    && pulseStatus.preview_entities > 0
    && windowOpen;
  useThreatPulseImpression('banner', isVisible);

  // The banner resolves its own visibility: useTopBanner keeps the shared top offset in sync from this report.
  useEffect(() => {
    reportThreatPulsePreviewBannerVisible(isVisible);
    return () => reportThreatPulsePreviewBannerVisible(false);
  }, [isVisible]);

  if (!isVisible) return null;

  const seen = t_i18n(
    'Threat Pulse preview: {count, plural, one {# of your objects is} other {# of your objects are}} seen across the community.',
    { values: { count: pulseStatus.preview_entities } },
  );
  const bannerText = isAdministrator
    ? seen
    : `${seen} ${t_i18n('Ask your administrator to turn on contribution in Settings > Filigran Experience.')}`;
  return (
    <TopBanner
      bannerColor="gradient_blue"
      bannerText={bannerText}
      buttonText={isAdministrator ? t_i18n('Set up contribution') : undefined}
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
 * One dismissable banner per user, the first day the Threat Pulse preview matches objects of the platform: the count
 * of local objects found in the community digest and the one step to the full experience.
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
