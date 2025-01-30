import { makeStyles } from '@mui/styles';
import React, { FunctionComponent, useEffect, useState } from 'react';
import Alert from '@mui/material/Alert';
import { graphql } from 'react-relay';
import qrcode from 'qrcode';
import Loader from '../../components/Loader';
import { QueryRenderer } from '../../relay/environment';
import { useFormatter } from '../../components/i18n';
import { OtpActivationQuery$data } from './__generated__/OtpActivationQuery.graphql';
import type { Theme } from '../../components/Theme';
import OtpInputField, { OTP_CODE_SIZE } from './OtpInputField';
import useApiMutation from '../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  input: {
    display: 'flex',
    justifyContent: 'center',
  },
}));

const generateOTP = graphql`
  query OtpActivationQuery {
    otpGeneration {
      secret
      uri
    }
  }
`;

const validateOtpPatch = graphql`
  mutation OtpActivationMutation($input: UserOTPActivationInput) {
    otpActivation(input: $input) {
      ...ProfileOverview_me
    }
  }
`;

interface OtpProps {
  secret: string;
  uri: string;
}

const Otp: FunctionComponent<OtpProps> = ({ secret, uri }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
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
        return setError(t_i18n('The code is not correct'));
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
  }, [uri, classes.color]);
  return (
    <div style={{ textAlign: 'center', margin: '0 auto', maxWidth: 500 }}>
      <img src={otpQrImage} style={{ width: 265 }} alt="" />
      {error ? (
        <Alert
          severity="error"
          variant="outlined"
          style={{ margin: '10px 0 10px 0' }}
        >
          {error}
        </Alert>
      ) : (
        <Alert
          severity="info"
          variant="outlined"
          style={{ margin: '10px 0 10px 0', justifyContent: 'center' }}
        >
          {t_i18n(
            'You need to activate a two-factor authentication. Please type the code generated in your application.',
          )}
        </Alert>
      )}
      <div className={classes.input}>
        <OtpInputField
          value={code}
          onChange={handleChange}
          isDisabled={inputDisable}
        />
      </div>
    </div>
  );
};

const OtpActivationComponent = () => (
  <QueryRenderer
    query={generateOTP}
    render={({ props }: { props: OtpActivationQuery$data }) => {
      if (props) {
        if (props.otpGeneration) {
          return (
            <Otp
              secret={props.otpGeneration.secret}
              uri={props.otpGeneration.uri}
            />
          );
        }
      }
      return <Loader />;
    }}
  />
);

export default OtpActivationComponent;
