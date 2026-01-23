import { Stack } from '@mui/material';
import Card from '../../../components/common/card/Card';
import { LoginRootPublicQuery$data } from '../../__generated__/LoginRootPublicQuery.graphql';
import LoginLayout from './LoginLayout';
import OtpValidation from './OtpValidation';
import AlertMfa from './AlertMfa';
import Button from '../../../components/common/button/Button';
import { useFormatter } from '../../../components/i18n';
import { APP_BASE_PATH } from '../../../relay/environment';

interface OtpValidationPageProps {
  settings: LoginRootPublicQuery$data['publicSettings'];
}

const OtpValidationPage = ({ settings }: OtpValidationPageProps) => {
  const { t_i18n } = useFormatter();

  return (
    <LoginLayout settings={settings}>
      <Stack gap={1} sx={{ width: 380 }}>
        <AlertMfa forceDisplay />

        <Card
          sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'start',
            gap: 2,
          }}
        >
          <OtpValidation />

          <Button
            size="small"
            variant="tertiary"
            sx={{ ml: -1.5 }}
            component="a"
            href={`${APP_BASE_PATH}/logout`}
          >
            {t_i18n('Back to login')}
          </Button>
        </Card>
      </Stack>
    </LoginLayout>
  );
};

export default OtpValidationPage;
