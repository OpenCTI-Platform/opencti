import React, { FunctionComponent } from 'react';
import OtpInput from 'react-otp-input';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../components/Theme';

export const OTP_CODE_SIZE = 6;

const useStyles = makeStyles<Theme>((theme) => ({
  inputStyle: {
    outline: 'none',
    border: `1px solid rgba(${
      theme.palette.mode === 'dark' ? '255,255,255' : '0,0,0'
    },.15)`,
    borderRadius: 4,
    minWidth: '54px',
    height: '54px',
    fontSize: theme.typography.h2.fontSize,
    fontWeight: theme.typography.h2.fontWeight,
    backgroundColor: 'transparent',
    margin: '0 5px 0 5px',
    color: theme.palette.text?.primary,
    "&:focus": {
      border: `2px solid ${theme.palette.primary.main}`,
    }
  },
}));

interface OtpInputField {
  value: string
  onChange: (data: string) => void
  isDisabled: boolean
}

const OtpInputField: FunctionComponent<OtpInputField> = ({
  value,
  onChange,
  isDisabled,
}) => {
  const classes = useStyles();

  return (
    <OtpInput
      value={value}
      onChange={onChange}
      numInputs={OTP_CODE_SIZE}
      inputType={'tel'}
      shouldAutoFocus={true}
      inputStyle={classes.inputStyle}
      renderInput={(props) => <input disabled={isDisabled} {...props} />}
    />
  );
}

export default OtpInputField;
