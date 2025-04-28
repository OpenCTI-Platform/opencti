import React, { useState } from 'react';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../components/i18n';
import type { Theme } from '../../components/Theme';
import OtpInputField, { OTP_CODE_SIZE } from './OtpInputField';
import useApiMutation from '../../utils/hooks/useApiMutation';
import { APP_BASE_PATH } from '../../relay/environment';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
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

const OTPForm = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [inputDisable, setInputDisable] = useState(false);
  const handleChange = (data: string) => setCode(data);
  const [commitOtpMutation] = useApiMutation(otpMutation);
  if (code.length === OTP_CODE_SIZE && !inputDisable) {
    setInputDisable(true);
    commitOtpMutation({
      variables: {
        input: { code },
      },
      onError: () => {
        setInputDisable(false);
        setCode('');
        setError(t_i18n('The code is not correct'));
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
          {t_i18n(
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
      <a
        href={`${APP_BASE_PATH}/logout`}
        rel="noreferrer"
      >
        {t_i18n('Back to login')}
      </a>
    </div>
  );
};

export default OTPForm;
