import React, { useContext, useEffect } from 'react';
import TopBanner from '../../../components/TopBanner';
import { useFormatter } from '../../../components/i18n';
import { useNavigate } from 'react-router-dom';
import { UserContext } from '../../../utils/hooks/useAuth';
import { REGISTER_BANNER_DISMISSED_BUS, REGISTER_BANNER_DISMISSED_KEY, resetRegisterBannerDismiss } from '../../../utils/bannerUtils';

const RegisterPlatformBanner = () => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const { settings } = useContext(UserContext);

  // Auto-reset dismissed state once the platform becomes registered
  useEffect(() => {
    if (settings?.xtm_hub_registration_status === 'registered') {
      resetRegisterBannerDismiss();
    }
  }, [settings?.xtm_hub_registration_status]);

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
