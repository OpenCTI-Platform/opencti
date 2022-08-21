import React, { useState } from 'react';
import { graphql } from 'react-relay';
import OtpInput from 'react-otp-input';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import Alert from '@mui/material/Alert';
import { commitMutation } from '../../relay/environment';
import { useFormatter } from '../../components/i18n';

const OPT_CODE_SIZE = 6;

const useStyles = makeStyles(() => ({
  otp: {
    textAlign: 'center',
    width: '100%',
    padding: 20,
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
  const theme = useTheme();
  const { t } = useFormatter();
  const [code, setCode] = useState('');
  const [error, setError] = useState(null);
  const [inputDisable, setInputDisable] = useState(false);
  const handleChange = (data) => setCode(data);
  const handleLogout = () => {
    commitMutation({
      mutation: logoutMutation,
      variables: {},
      onCompleted: () => window.location.reload(),
    });
  };
  if (code.length === OPT_CODE_SIZE && !inputDisable) {
    setInputDisable(true);
    commitMutation({
      mutation: otpMutation,
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
          style={{ margin: '0 0 20px 0' }}
        >
          {error}
        </Alert>
      ) : (
        <Alert
          severity="info"
          variant="outlined"
          style={{ margin: '0 0 20px 0' }}
        >
          {t('Type the code generated in your application')}
        </Alert>
      )}
      <div style={{ marginLeft: 9 }}>
        <OtpInput
          value={code}
          onChange={handleChange}
          numInputs={OPT_CODE_SIZE}
          isDisabled={inputDisable}
          isInputNum={true}
          shouldAutoFocus={true}
          inputStyle={{
            outline: 'none',
            border: `1px solid rgba(${
              theme.palette.mode === 'dark' ? '255,255,255' : '0,0,0'
            },.15)`,
            borderRadius: 4,
            width: '54px',
            height: '54px',
            fontSize: '16px',
            fontWeight: '400',
            backgroundColor: 'transparent',
            margin: '0 5px 0 5px',
            color: theme.palette.text.primary,
          }}
          focusStyle={{
            border: `2px solid ${theme.palette.primary.main}`,
            outline: 'none',
          }}
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
