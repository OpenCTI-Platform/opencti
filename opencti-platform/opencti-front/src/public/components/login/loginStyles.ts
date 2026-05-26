export const LOGIN_TEXT_COLOR = '#111827';
export const LOGIN_INPUT_BG = '#FFFFFF';
export const LOGIN_BORDER_COLOR = '#E5E7EB';
export const LOGIN_BORDER_HOVER_COLOR = '#D1D5DB';
export const LOGIN_BORDER_FOCUS_COLOR = '#533DE4';
export const LOGIN_BRAND_COLOR = '#533DE4';

const loginAutofillSelectors = [
  '& input:-webkit-autofill',
  '& input:-webkit-autofill:hover',
  '& input:-webkit-autofill:focus',
  '& input:-webkit-autofill:active',
  '& .MuiInputBase-input:-webkit-autofill',
  '& .MuiInputBase-input:-webkit-autofill:hover',
  '& .MuiInputBase-input:-webkit-autofill:focus',
  '& .MuiInputBase-input:-webkit-autofill:active',
].join(', ');

const loginInputBaseSx = {
  '& .MuiOutlinedInput-root': {
    borderRadius: '8px',
    backgroundColor: `${LOGIN_INPUT_BG} !important`,
    color: `${LOGIN_TEXT_COLOR} !important`,
    minHeight: 42,
    '& fieldset': {
      borderColor: LOGIN_BORDER_COLOR,
    },
    '&:hover fieldset': {
      borderColor: LOGIN_BORDER_HOVER_COLOR,
    },
    '&.Mui-focused fieldset': {
      borderColor: LOGIN_BORDER_FOCUS_COLOR,
    },
  },
  '& .MuiInputBase-root': {
    color: `${LOGIN_TEXT_COLOR} !important`,
    backgroundColor: `${LOGIN_INPUT_BG} !important`,
  },
  '& .MuiOutlinedInput-input': {
    padding: '10px 12px',
    fontSize: 14,
    lineHeight: 1.4,
  },
  '& .MuiInputBase-input': {
    color: `${LOGIN_TEXT_COLOR} !important`,
    WebkitTextFillColor: `${LOGIN_TEXT_COLOR} !important`,
    caretColor: `${LOGIN_TEXT_COLOR} !important`,
  },
  [loginAutofillSelectors]: {
    WebkitTextFillColor: `${LOGIN_TEXT_COLOR} !important`,
    WebkitBoxShadow: `0 0 0 1000px ${LOGIN_INPUT_BG} inset !important`,
    boxShadow: `0 0 0 1000px ${LOGIN_INPUT_BG} inset !important`,
    caretColor: `${LOGIN_TEXT_COLOR} !important`,
    transition: 'background-color 5000s ease-in-out 0s',
  },
};

export const loginPanelSx = {
  backgroundColor: LOGIN_INPUT_BG,
  color: LOGIN_TEXT_COLOR,
  ...loginInputBaseSx,
};

export const loginFieldGroupSx = {
  display: 'flex',
  flexDirection: 'column',
  gap: 0.75,
};

export const loginFieldLabelSx = {
  fontSize: 14,
  fontWeight: 600,
  color: '#374151',
  lineHeight: 1.25,
};

export const loginInputSx = loginInputBaseSx;

export const loginRememberMeSx = {
  m: 0,
  ml: 0,
  mr: 0,
  alignItems: 'center',
  '& .MuiCheckbox-root': {
    p: 0,
    marginInlineEnd: 1,
  },
  '& .MuiFormControlLabel-label': {
    p: 0,
    m: 0,
  },
};
