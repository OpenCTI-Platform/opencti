import { FunctionComponent, useState } from 'react';
import LoginForm from './LoginForm';
import { LoginRootPublicQuery$data } from '../../__generated__/LoginRootPublicQuery.graphql';
import { isNotEmptyField } from '../../../utils/utils';
import ResetPassword from './ResetPassword';
import ExternalAuths from './ExternalAuths';
import AlertLogout from './AlertLogout';
import AlertFlashError from './AlertFlashError';
import ConsentMessage from './ConsentMessage';
import LoginLayout from './LoginLayout';
import Card from '../../../components/common/card/Card';
import { Stack, Typography } from '@mui/material';
import LoginMarkdown from './LoginMarkdown';
import AlertValidateOtp from './AlertValidateOtp';
import AlertChangePwd from './AlertChangePwd';
import { useLoginContext } from './loginContext';
import AlertMfa from './AlertMfa';
import { useFormatter } from '../../../components/i18n';

interface LoginPageProps {
  settings: LoginRootPublicQuery$data['publicSettings'];
}

const LoginPage: FunctionComponent<LoginPageProps> = ({ settings }) => {
  const { t_i18n } = useFormatter();
  const { resetPwdStep } = useLoginContext();
  const [checked, setChecked] = useState(false);

  const consentMessage = settings.platform_consent_message;
  const loginMessage = settings.platform_login_message;
  const providers = settings.platform_providers;
  const hasAuthForm = providers.filter((p) => p?.type === 'FORM').length > 0;
  const hasConsentMessage = isNotEmptyField(consentMessage);

  const handleChange = () => {
    setChecked(!checked);
    // Auto scroll to bottom of unhidden/re-hidden login options.
    window.setTimeout(() => {
      const scrollingElement = document.scrollingElement ?? document.body;
      scrollingElement.scrollTop = scrollingElement.scrollHeight;
    }, 1);
  };

  const consentOk = !hasConsentMessage || (hasConsentMessage && checked);
  const showLoginForm = consentOk && hasAuthForm && !resetPwdStep;

  return (
    <LoginLayout settings={settings}>
      <Stack gap={1} sx={{ width: 500 }}>
        <ConsentMessage
          value={checked}
          data={settings}
          onToggle={handleChange}
        />

        <AlertLogout />
        <AlertFlashError />
        <AlertValidateOtp />
        <AlertChangePwd />
        <AlertMfa />

        {providers.length === 0 && (
          <Card>
            <Typography textAlign="center" variant="body2">
              {t_i18n('No authentication provider available')}
            </Typography>
          </Card>
        )}

        {consentOk && providers.length > 0 && (
          <Card
            sx={{
              display: 'flex',
              flexDirection: 'column',
            }}
          >
            {!!loginMessage && (
              <LoginMarkdown sx={{ mb: 2 }}>
                {loginMessage}
              </LoginMarkdown>
            )}

            {(showLoginForm || !!resetPwdStep) && (
              <div style={{ minHeight: 170 }}>
                {!!resetPwdStep && <ResetPassword />}
                {showLoginForm && <LoginForm />}
              </div>
            )}
          </Card>
        )}

        <ExternalAuths
          data={settings}
          consentValue={checked}
        />
      </Stack>
    </LoginLayout>
  );
};

export default LoginPage;
