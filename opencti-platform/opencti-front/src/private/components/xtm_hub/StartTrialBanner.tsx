import React, { useContext } from 'react';
import TopBanner from '../../../components/TopBanner';
import { isEmptyField } from '../../../utils/utils';
import { UserContext } from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../../components/i18n';

const StartTrialBanner = () => {
  const { settings } = useContext(UserContext);
  const { t_i18n } = useFormatter();

  if (!settings || isEmptyField(settings?.platform_xtmhub_url) || !settings.platform_demo) return <></>;

  const freeTrialUrl = `${settings?.platform_xtmhub_url}/redirect/free-trial`;
  const createFreeTrialUrl = `${settings?.platform_xtmhub_url}/redirect/create-free-trial`;

  const text = (<>
    {t_i18n('Come and Try OpenCTI with the ')}
    <strong> {t_i18n('Free Trial Instance')}</strong>!
    <strong><u><a href={freeTrialUrl} style={{ color: '#000000', marginLeft: '4px' }} target="_blank" rel="noreferrer">Learn more</a></u></strong>
  </>);

  const handleOpenLink = () => {
    window.open(createFreeTrialUrl, '_blank', 'noopener,noreferrer');
  };

  return (
    <TopBanner bannerColor="gradient_blue" bannerText={text} buttonText={t_i18n('Start a Trial')} onButtonClick={handleOpenLink}/>);
};

export default StartTrialBanner;
