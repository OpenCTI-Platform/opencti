import React, { useState } from 'react';
import { graphql } from 'react-relay';
import OtpInput from 'react-otp-input';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { commitMutation } from '../../relay/environment';
import { useFormatter } from '../../components/i18n';

const OPT_CODE_SIZE = 6;

const useStyles = makeStyles(() => ({
  otp: {
    padding: 15,
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
        window.location.reload();
      },
      onCompleted: () => {
        window.location.reload();
      },
    });
  }
  return (
    <div className={classes.otp}>
      <h2>{t('Two-factor Verification')}</h2>
      <div>
        <OtpInput
          value={code}
          onChange={handleChange}
          numInputs={OPT_CODE_SIZE}
          isDisabled={inputDisable}
          separator={<span style={{ width: '8px' }}></span>}
          isInputNum={true}
          shouldAutoFocus={true}
          inputStyle={{
            border: '1px solid transparent',
            borderRadius: '8px',
            width: '54px',
            height: '54px',
            fontSize: '16px',
            color: '#000',
            fontWeight: '400',
            caretColor: 'blue',
          }}
          focusStyle={{
            border: '1px solid #CFD3DB',
            outline: 'none',
          }}
        />
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
    </div>
  );
};

export default OTPForm;
