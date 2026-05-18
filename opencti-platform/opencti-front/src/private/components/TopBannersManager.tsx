import React, { useContext, useState } from 'react';
import { UserContext } from '../../utils/hooks/useAuth';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from '../../utils/hooks/useGranted';
import useHelper from '../../utils/hooks/useHelper';
import { REGISTER_BANNER_DISMISSED_BUS, readRegisterDismissed, shouldDisplayLicenseBanner, shouldDisplayRegisterBanner, shouldDisplayTrialBanner } from '../../utils/bannerUtils';
import LicenseBanner from './LicenseBanner';
import StartTrialBanner from './xtm_hub/StartTrialBanner';
import RegisterPlatformBanner from './xtm_hub/RegisterPlatformBanner';
import useBus from '../../utils/hooks/useBus';

const TopBannersManager = () => {
  const { settings, isXTMHubAccessible } = useContext(UserContext);
  const isGrantedToXtmHub = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const { isFeatureEnable } = useHelper();

  const [isDismissed, setIsDismissed] = useState<boolean>(readRegisterDismissed);
  useBus(REGISTER_BANNER_DISMISSED_BUS, setIsDismissed, []);

  const showLicenseBanner = shouldDisplayLicenseBanner(settings?.platform_enterprise_edition);
  const showTrialBanner = shouldDisplayTrialBanner(settings);
  const showRegisterBanner = isFeatureEnable('XTMHUB_NEWS_FEED_ENABLED') && shouldDisplayRegisterBanner(
    settings,
    isXTMHubAccessible,
    isGrantedToXtmHub,
    isDismissed,
  );

  return (
    <>
      {showLicenseBanner && <LicenseBanner />}
      {showTrialBanner && <StartTrialBanner />}
      {showRegisterBanner && <RegisterPlatformBanner />}
    </>
  );
};

export default TopBannersManager;
