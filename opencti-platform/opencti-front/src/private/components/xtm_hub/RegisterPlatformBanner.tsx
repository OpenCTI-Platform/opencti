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
      <strong>{t_i18n('New feeds are available.')}</strong> {t_i18n('Register your platform to access and deploy them in one click.')}
    </>
  );

  return (
    <TopBanner
      bannerColor="gradient_blue"
      bannerText={text}
      buttonText={t_i18n('Register Platform')}
      onButtonClick={() => navigate('/dashboard/settings/experience')}
      buttonSx={{ backgroundColor: '#007399', color: '#ffffff', fontWeight: 'bold' }}
      dismissible
      dismissKey={REGISTER_BANNER_DISMISSED_KEY}
      dismissBus={REGISTER_BANNER_DISMISSED_BUS}
    />
  );
};

export default RegisterPlatformBanner;
