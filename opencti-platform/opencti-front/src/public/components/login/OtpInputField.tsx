import React, { FunctionComponent } from 'react';
import OtpInput from 'react-otp-input';
import { styled } from '@mui/material/styles';
import { useFormatter } from '../../../components/i18n';

export const OTP_CODE_SIZE = 6;

const DigitInput = styled('input')(({ theme }) => ({
  outline: 'none',
  border: `1px solid rgba(${
    theme.palette.mode === 'dark' ? '255,255,255' : '0,0,0'
  },.15)`,
  borderRadius: 4,
  minWidth: '42px',
  height: '54px',
  fontSize: theme.typography.h2.fontSize,
  fontWeight: theme.typography.h2.fontWeight,
  backgroundColor: 'transparent',
  color: theme.palette.text?.primary,
  '&:focus': {
    border: `2px solid ${theme.palette.primary.main}`,
  },
}));

interface OtpInputFieldProps {
  value: string;
  onChange: (data: string) => void;
  isDisabled: boolean;
}

const OtpInputField: FunctionComponent<OtpInputFieldProps> = ({
  value,
  onChange,
  isDisabled,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <OtpInput
      aria-label={t_i18n('one-time password')}
      value={value}
      onChange={onChange}
      numInputs={OTP_CODE_SIZE}
      inputType="tel"
      shouldAutoFocus={true}
      containerStyle={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        width: '100%',
      }}
      renderInput={(props) => <DigitInput disabled={isDisabled} {...props} />}
    />
  );
};

export default OtpInputField;
