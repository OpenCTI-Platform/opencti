export default {
  fontFamily: 'Roboto, sans-serif',
  palette: {
    type: 'light',
    primary: { main: '#507bc8' },
    secondary: { main: '#ff3d00' },
    header: { background: '#ffffff', text: '#000000' },
    navAlt: { background: '#ffffff', backgroundHeader: '#fafafa' },
    navBottom: { background: '#ffffff' },
    background: {
      paper: '#ffffff',
      paperLight: '#fafafa',
      nav: '#ffffff',
      navLight: '#ffffff',
      default: '#fafafa',
      chip: 'rgba(80, 123, 200, 0.6)',
    },
    action: { disabled: '#747474', grid: '#dbdbdb' },
  },
  typography: {
    useNextVariants: true,
    body2: {
      fontSize: '0.8rem',
    },
    body1: {
      fontSize: '0.9rem',
    },
    h1: {
      margin: '0 0 10px 0',
      padding: 0,
      color: '#507bc8',
      fontWeight: 400,
      fontSize: 22,
    },
    h2: {
      margin: '0 0 10px 0',
      padding: 0,
      color: '#000000',
      fontWeight: 500,
      fontSize: 16,
      textTransform: 'uppercase',
    },
    h3: {
      margin: '0 0 10px 0',
      padding: 0,
      color: '#507bc8',
      fontWeight: 400,
      fontSize: 13,
    },
    h4: {
      margin: '0 0 10px 0',
      padding: 0,
      textTransform: 'uppercase',
      fontSize: 12,
      fontWeight: 500,
      color: '#4b4b4b',
    },
    h5: {
      color: '#000000',
      fontWeight: 400,
      fontSize: 13,
      textTransform: 'uppercase',
      marginTop: -4,
    },
    h6: {
      color: '#000000',
      fontWeight: 400,
      fontSize: 18,
    },
  },
  overrides: {
    MuiCssBaseline: {
      '@global': {
        '*': {
          scrollbarColor: '#f0f0f0 #c6c6c6',
        },
        '*::-webkit-scrollbar': {
          width: 12,
        },
        '*::-webkit-scrollbar-track': {
          background: '#f0f0f0',
        },
        '*::-webkit-scrollbar-thumb': {
          backgroundColor: '#c6c6c6',
          borderRadius: 0,
          border: '3px solid #c6c6c6',
        },
        html: {
          WebkitFontSmoothing: 'auto',
        },
        a: {
          color: '#507bc8',
        },
        'input:-webkit-autofill': {
          '-webkit-animation': 'autofill 0s forwards',
          animation: 'autofill 0s forwards',
          '-webkit-text-fill-color': '#000000 !important',
          caretColor: 'transparent !important',
          '-webkit-box-shadow': '0 0 0 1000px #f8f8f8 inset !important',
          borderTopLeftRadius: 'inherit',
          borderTopRightRadius: 'inherit',
        },
        pre: {
          background: 'rgba(0, 0, 0, 0.02)',
        },
        code: {
          background: 'rgba(0, 0, 0, 0.02)',
        },
      },
    },
  },
};
