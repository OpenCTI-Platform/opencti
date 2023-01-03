import React, { useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import OtpInput from 'react-otp-input';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../components/i18n';
import { Theme } from '../../components/Theme';

const OPT_CODE_SIZE = 6;

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
  inputStyle: {
    outline: 'none',
    border: `1px solid rgba(${
      theme.palette.mode === 'dark' ? '255,255,255' : '0,0,0'
    },.15)`,
    borderRadius: 4,
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
  if (code.length === OPT_CODE_SIZE && !inputDisable) {
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
          {t('You need to validate your two-factor authentication. Please type the code generated in your application')}
        </Alert>
      )}
      <div className={classes.input}>
        <OtpInput
          value={code}
          onChange={handleChange}
          numInputs={OPT_CODE_SIZE}
          isDisabled={inputDisable}
          isInputNum={true}
          shouldAutoFocus={true}
          inputStyle={classes.inputStyle}
          focusStyle={classes.focusStyle}
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
