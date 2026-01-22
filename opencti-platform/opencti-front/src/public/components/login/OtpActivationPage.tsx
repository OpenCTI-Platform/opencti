import { FunctionComponent, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import qrcode from 'qrcode';
import Loader from '../../../components/Loader';
import { APP_BASE_PATH, QueryRenderer } from '../../../relay/environment';
import { useFormatter } from '../../../components/i18n';
import OtpInputField, { OTP_CODE_SIZE } from './OtpInputField';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { LoginRootPublicQuery$data } from '../../__generated__/LoginRootPublicQuery.graphql';
import LoginLayout from './LoginLayout';
import { Stack } from '@mui/material';
import LoginAlert from './LoginAlert';
import Card from '../../../components/common/card/Card';
import Button from '../../../components/common/button/Button';
import { OtpActivationPageQuery$data } from './__generated__/OtpActivationPageQuery.graphql';

const generateOtp = graphql`
  query OtpActivationPageQuery {
    otpGeneration {
      secret
      uri
    }
  }
`;

const validateOtpPatch = graphql`
  mutation OtpActivationPageMutation($input: UserOTPActivationInput) {
    otpActivation(input: $input) {
      ...ProfileOverview_me
    }
  }
`;

interface OtpProps {
  secret: string;
  uri: string;
  settings: LoginRootPublicQuery$data['publicSettings'];
}

const Otp: FunctionComponent<OtpProps> = ({ secret, uri, settings }) => {
  const { t_i18n } = useFormatter();
  const [otpQrImage, setOtpQrImage] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [inputDisable, setInputDisable] = useState(false);
  const handleChange = (data: string) => setCode(data);
  const [commit] = useApiMutation(validateOtpPatch);

  if (code.length === OTP_CODE_SIZE && !inputDisable) {
    setInputDisable(true);
    commit({
      variables: { input: { secret, code } },
      onError: () => {
        setInputDisable(false);
        setCode('');
        return setError(t_i18n('The code is not correct.'));
      },
      onCompleted: () => {
        window.location.reload();
      },
    });
  }

  useEffect(() => {
    qrcode.toDataURL(
      uri,
      (err: Error | null | undefined, imageUrl: string) => {
        if (err) {
          setOtpQrImage('');
          return;
        }
        setOtpQrImage(imageUrl);
      },
    );
  }, [uri]);

  const alertSeverity = error ? 'error' : 'info';
  const alertMessage = error
    ? error
    : t_i18n('You need to activate a two-factor authentication. Please type the code generated in your application.');

  return (
    <LoginLayout settings={settings}>
      <Stack gap={1} sx={{ width: 380 }}>
        <LoginAlert severity={alertSeverity}>
          {alertMessage}
        </LoginAlert>
        <Card
          sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 3,
          }}
        >
          <img src={otpQrImage} style={{ width: 265 }} alt="" />
          <OtpInputField
            value={code}
            onChange={handleChange}
            isDisabled={inputDisable}
          />
          <a
            href={`${APP_BASE_PATH}/logout`}
            rel="noreferrer"
          >
            <Button
              size="small"
              variant="tertiary"
            >
              {t_i18n('Back to login')}
            </Button>
          </a>
        </Card>
      </Stack>
    </LoginLayout>
  );
};

const OtpActivationPage = ({ settings }: Pick<OtpProps, 'settings'>) => (
  <QueryRenderer
    query={generateOtp}
    render={({ props }: { props: OtpActivationPageQuery$data }) => {
      if (props && props.otpGeneration) {
        return (
          <Otp
            secret={props.otpGeneration.secret}
            uri={props.otpGeneration.uri}
            settings={settings}
          />
        );
      }
      return <Loader />;
    }}
  />
);

export default OtpActivationPage;
