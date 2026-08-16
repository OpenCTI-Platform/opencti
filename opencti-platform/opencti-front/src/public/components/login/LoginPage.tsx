import { FunctionComponent, useEffect, useRef, useState } from 'react';
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
import ForcePasswordChange from './ForcePasswordChange';

interface LoginPageProps {
  settings: LoginRootPublicQuery$data['publicSettings'];
}

/**
 * The login page's surfaces sit on ELEVATION LAYER 1.
 *
 * `Card` paints `background.secondary` on the built-in themes, and that field
 * is a hardcoded `#0C1524` in dark — no elevation step at all (RGB distance 7
 * from layer 1, 15 from layer 0). In light it is `#FFFFFF`, which already IS
 * layer 1, so only dark moves.
 *
 * The correction is AT THE SITE, exactly as it was done in OpenAEV: the panel
 * stops taking that field and falls back to the right layer. `background.paper`
 * resolves to `--bg-elevation-default-layer-1` and keeps following a customer's
 * `theme_paper` — which is what `Card` itself already does on a custom theme.
 * `background.secondary` is left untouched for its 9 consumers and Card's 164
 * other sites; repointing the field would repaint all of them and is a separate
 * decision.
 */
const LOGIN_SURFACE_SX = { backgroundColor: 'background.paper' } as const;

const LoginPage: FunctionComponent<LoginPageProps> = ({ settings }) => {
  const { t_i18n } = useFormatter();
  const { resetPwdStep, forcePasswordChange } = useLoginContext();
  const [checked, setChecked] = useState(false);

  const loginMessageRef = useRef<HTMLElement>(null);
  const [isLoginMessageOverflowing, setIsLoginMessageOverflowing] = useState(false);
  const loginMessageMaxHeight = window.innerHeight * 0.25;

  const consentMessage = settings.platform_consent_message;
  const loginMessage = settings.platform_login_message;
  const providers = settings.platform_providers;
  const hasAuthForm = providers.filter((p) => p?.type === 'FORM').length > 0;
  const hasConsentMessage = isNotEmptyField(consentMessage);

  useEffect(() => {
    if (loginMessageRef.current) {
      setIsLoginMessageOverflowing(loginMessageRef.current.scrollHeight > loginMessageMaxHeight);
    }
  }, [loginMessage]);

  const handleChange = () => {
    setChecked(!checked);
    // Auto scroll to bottom of unhidden/re-hidden login options.
    window.setTimeout(() => {
      const scrollingElement = document.scrollingElement ?? document.body;
      scrollingElement.scrollTop = scrollingElement.scrollHeight;
    }, 1);
  };

  const consentOk = !hasConsentMessage || (hasConsentMessage && checked);
  const showLoginForm = consentOk && hasAuthForm && !resetPwdStep && !forcePasswordChange;

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
          <Card sx={LOGIN_SURFACE_SX}>
            <Typography textAlign="center" variant="body2">
              {t_i18n('No authentication provider available')}
            </Typography>
          </Card>
        )}

        {!!loginMessage && (
          <Typography
            ref={loginMessageRef}
            textAlign="center"
            variant="body2"
            sx={{
              maxHeight: loginMessageMaxHeight,
              overflowY: isLoginMessageOverflowing ? 'auto' : undefined,
            }}
          >
            <LoginMarkdown sx={{ mb: 2 }}>
              {loginMessage}
            </LoginMarkdown>
          </Typography>
        )}

        {consentOk
          && providers.filter((p) => p.type === 'FORM').length > 0
          && (showLoginForm || !!resetPwdStep || !!forcePasswordChange)
          && (
            <Card
              sx={{
                ...LOGIN_SURFACE_SX,
                display: 'flex',
                flexDirection: 'column',
              }}
            >
              <div style={{ minHeight: 170 }}>
                {!!resetPwdStep && (
                  <ResetPassword
                    policies={{
                      minLength: settings.password_policy_min_length,
                      maxLength: settings.password_policy_max_length,
                      minSymbols: settings.password_policy_min_symbols,
                      minNumbers: settings.password_policy_min_numbers,
                      minWords: settings.password_policy_min_words,
                      minLowercase: settings.password_policy_min_lowercase,
                      minUppercase: settings.password_policy_min_uppercase,
                    }}
                  />
                )}
                {!!forcePasswordChange && (
                  <ForcePasswordChange
                    policies={{
                      minLength: settings.password_policy_min_length,
                      maxLength: settings.password_policy_max_length,
                      minSymbols: settings.password_policy_min_symbols,
                      minNumbers: settings.password_policy_min_numbers,
                      minWords: settings.password_policy_min_words,
                      minLowercase: settings.password_policy_min_lowercase,
                      minUppercase: settings.password_policy_min_uppercase,
                    }}
                  />
                )}
                {showLoginForm && <LoginForm />}
              </div>
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
