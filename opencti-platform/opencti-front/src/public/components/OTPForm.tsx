import React, { useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../components/i18n';
import { Theme } from '../../components/Theme';
import OtpInputField, { OTP_CODE_SIZE } from './OtpInputField';

const useStyles = makeStyles<Theme>((theme) => ({
  otp: {
    textAlign: 'center',
    width: '100%',
    padding: 20,
  },
  input: {
    display: 'flex',
    justifyContent: 'center',
  },
}));

const otpMutation = graphql`
  mutation OTPFormMutation($input: UserOTPLoginInput) {
    otpLogin(input: $input)
  }
`;

const logoutMutation = graphql`
  mutation OTPFormLogoutMutation {
    logout
  }
`;

const OTPForm = () => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [inputDisable, setInputDisable] = useState(false);
  const handleChange = (data: string) => setCode(data);
  const [commitLogoutMutation] = useMutation(logoutMutation);
  const [commitOtpMutation] = useMutation(otpMutation);
  const handleLogout = () => {
    commitLogoutMutation({
      variables: {},
      onCompleted: () => window.location.reload(),
    });
  };
  if (code.length === OTP_CODE_SIZE && !inputDisable) {
    setInputDisable(true);
    commitOtpMutation({
      variables: {
        input: { code },
      },
      onError: () => {
        setInputDisable(false);
        setCode('');
        setError(t('The code is not correct'));
      },
      onCompleted: () => {
        window.location.reload();
      },
    });
  }
  return (
    <div className={classes.otp}>
      {error ? (
        <Alert
          severity="error"
          variant="outlined"
          style={{ margin: '0 0 15px 0' }}
        >
          {error}
        </Alert>
      ) : (
        <Alert
          severity="info"
          variant="outlined"
          style={{ margin: '15px 0', justifyContent: 'center' }}
        >
          {t(
            'You need to validate your two-factor authentication. Please type the code generated in your application',
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
      <Button
        type="submit"
        variant="contained"
        color="primary"
        onClick={handleLogout}
        style={{ marginTop: 30 }}
      >
        {t('Cancel')}
      </Button>
    </div>
  );
};

export default OTPForm;
