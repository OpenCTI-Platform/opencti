import { makeStyles } from '@mui/styles';
import React, { FunctionComponent, useEffect, useState } from 'react';
import Alert from '@mui/material/Alert';
import OtpInput from 'react-otp-input';
import { graphql, useMutation } from 'react-relay';
import qrcode from 'qrcode';
import { useTheme } from '@mui/material/styles';
import Loader from '../../components/Loader';
import { QueryRenderer } from '../../relay/environment';
import { useFormatter } from '../../components/i18n';
import { OtpActivationQuery$data } from './__generated__/OtpActivationQuery.graphql';
import { Theme } from '../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  input: {
    display: 'flex',
    justifyContent: 'center',
  },
  inputStyle: {
    outline: 'none',
    border: `1px solid rgba(${
      theme.palette.mode === 'dark' ? '255,255,255' : '0,0,0'
    },.15)`,
    borderRadius: 4,
    boxSizing: 'border-box',
    minWidth: '54px',
    height: '54px',
    fontSize: '16px',
    fontWeight: '400',
    backgroundColor: 'transparent',
    margin: '0 5px 0 5px',
    color: theme.palette.primary.main,
  },
  focusStyle: {
    border: `2px solid ${theme.palette.primary.main}`,
    outline: 'none',
  },
}));

export const OTP_CODE_SIZE = 6;

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
  const { t } = useFormatter();
  const classes = useStyles();
  const theme = useTheme();
  const [otpQrImage, setOtpQrImage] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [inputDisable, setInputDisable] = useState(false);
  const handleChange = (data: string) => setCode(data);
  const [commit] = useMutation(validateOtpPatch);

  if (code.length === OTP_CODE_SIZE && !inputDisable) {
    setInputDisable(true);
    commit({
      variables: { input: { secret, code } },
      onError: () => {
        setInputDisable(false);
        setCode('');
        return setError(t('The code is not correct'));
      },
      onCompleted: () => {
        window.location.reload();
      },
    });
  }
  useEffect(() => {
    qrcode.toDataURL(
      uri,
      {
        color: {
          dark: `${theme.palette.mode}` === 'dark' ? '#ffffff' : '#000000',
          light: '#0000', // Transparent background
        },
      },
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
    <div style={{ textAlign: 'center' }}>
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
          {t(
            'You need to activate a two-factor authentication. Please type the code generated in your application.',
          )}
        </Alert>
      )}
      <div className={classes.input}>
        <OtpInput
          value={code}
          onChange={handleChange}
          numInputs={OTP_CODE_SIZE}
          isDisabled={inputDisable}
          isInputNum={true}
          shouldAutoFocus={true}
          inputStyle={classes.inputStyle}
          focusStyle={classes.focusStyle}
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
