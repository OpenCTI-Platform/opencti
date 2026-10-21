import React, { useEffect } from 'react';
import useTopBanner from '../../utils/hooks/useTopBanner';
import LicenseBanner from './LicenseBanner';
import StartTrialBanner from './xtm_hub/StartTrialBanner';
import RegisterPlatformBanner from './xtm_hub/RegisterPlatformBanner';
import SmtpRefreshTokenBanner from './settings/smtp_configuration/SmtpRefreshTokenBanner';
import ThreatPulsePreviewBanner from './common/threat_pulse/ThreatPulsePreviewBanner';
import useAuth from '../../utils/hooks/useAuth';
import { resetRegisterBannerDismiss } from '../../utils/bannerUtils';

const TopBannersManager = () => {
  const { showLicenseBanner, showTrialBanner, showRegisterBanner, showSmtpRefreshTokenBanner } = useTopBanner();
  const { settings } = useAuth();
  // Every banner sits at the same place under the top bar: the Threat Pulse preview, informational only, waits
  // until no other banner is shown.
  const otherBannerShown = showLicenseBanner || showTrialBanner || showRegisterBanner || showSmtpRefreshTokenBanner;

  // Auto-reset dismissed state once the platform becomes registered,
  // so the banner reappears if the platform later becomes unregistered.
  useEffect(() => {
    if (settings?.xtm_hub_registration_status === 'registered') {
      resetRegisterBannerDismiss();
    }
  }, [settings?.xtm_hub_registration_status]);

  return (
    <>
      {showLicenseBanner && <LicenseBanner />}
      {showTrialBanner && <StartTrialBanner />}
      {showRegisterBanner && <RegisterPlatformBanner />}
      <SmtpRefreshTokenBanner />
      {!otherBannerShown && <ThreatPulsePreviewBanner />}
    </>
  );
};

export default TopBannersManager;
