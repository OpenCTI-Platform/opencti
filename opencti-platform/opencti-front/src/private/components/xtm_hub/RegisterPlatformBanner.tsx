import React from 'react';
import TopBanner from '../../../components/TopBanner';
import { useFormatter } from '../../../components/i18n';
import { useNavigate } from 'react-router-dom';
import { REGISTER_BANNER_DISMISSED_BUS, REGISTER_BANNER_DISMISSED_KEY } from '../../../utils/bannerConstants';

const RegisterPlatformBanner = () => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();

  const text = (
    <>
      <strong>{t_i18n('New feeds are available.')}</strong> {t_i18n('Connect your product to access and deploy these feeds in one click.')}
    </>
  );

  return (
    <TopBanner
      bannerColor="gradient_blue"
      bannerText={text}
      buttonText={t_i18n('Connect Product')}
      onButtonClick={() => navigate('/redirect/connect-xtm-hub')}
      buttonSx={{ backgroundColor: '#007399', color: '#ffffff', fontWeight: 'bold' }}
      dismissible
      dismissKey={REGISTER_BANNER_DISMISSED_KEY}
      dismissBus={REGISTER_BANNER_DISMISSED_BUS}
    />
  );
};

export default RegisterPlatformBanner;
