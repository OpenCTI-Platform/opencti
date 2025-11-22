import React, { useContext } from 'react';
import moment from 'moment/moment';
import { UserContext } from '../../utils/hooks/useAuth';
import { dateFormat, daysBetweenDates, now } from '../../utils/Time';
import TopBanner, { TopBannerColor } from '../../components/TopBanner';
import { useFormatter } from '../../components/i18n';
import { RootSettings$data } from '../__generated__/RootSettings.graphql';
import useHelper from '../../utils/hooks/useHelper';

export const LICENSE_OPTION_TRIAL = 'trial';

interface BannerInfo {
  message: React.ReactNode;
  bannerColor: TopBannerColor;
  buttonText ?: string;
}

const getBannerColor = (remainingDays: number) => {
  if (remainingDays <= 8) return 'gradient_yellow';
  if (remainingDays <= 22) return 'gradient_green';
  return 'gradient_blue';
};

const computeBannerInfo = (eeSettings: RootSettings$data['platform_enterprise_edition']): BannerInfo | undefined => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  if (!eeSettings.license_validated) {
    return {
      message: `The current ${eeSettings.license_type} license has expired, Enterprise Edition is disabled.`,
      bannerColor: 'red',
    };
  } if (eeSettings.license_extra_expiration) {
    return {
      message: `The current ${eeSettings.license_type} license has expired, Enterprise Edition will be disabled in ${eeSettings.license_extra_expiration_days} days.`,
      bannerColor: 'red',
    };
  } if (eeSettings.license_type === LICENSE_OPTION_TRIAL) {
    const featureFlagFreeTrials = isFeatureEnable('FREE_TRIALS');
    if (featureFlagFreeTrials) {
      const remainingDays = daysBetweenDates(now(), moment(eeSettings.license_expiration_date));
      const bannerColor = getBannerColor(remainingDays);
      return {
        buttonText: t_i18n('Contact us'),
        bannerColor,
        message: (
          <>
            {t_i18n('Your OpenCTI Enterprise Edition free trial is active: ')}
            <strong> {remainingDays} {remainingDays === 1 ? t_i18n('Day remaining') : t_i18n('Days remaining')}</strong>
          </>
        ),
      };
    }
    return {
      message: `This is a trial Enterprise Edition version, valid until ${dateFormat(eeSettings.license_expiration_date)}.`,
      bannerColor: 'yellow',
    };
  }
  return undefined;
};

const LicenceBanner = () => {
  const { settings } = useContext(UserContext);
  const eeSettings = settings?.platform_enterprise_edition;
  const isEE = eeSettings?.license_enterprise;
  if (!isEE) return <></>;

  const bannerInfo = computeBannerInfo(eeSettings);
  if (!bannerInfo) return <></>;

  return (
    <TopBanner bannerColor={bannerInfo.bannerColor} bannerText={bannerInfo.message} buttonText={bannerInfo.buttonText} onButtonClick={() => {}}/>
  );
};

export default LicenceBanner;
