export default {
  fontFamily: 'Roboto, sans-serif',
  palette: {
    type: 'light',
    primary: { main: '#507bc8' },
    secondary: { main: '#ff3d00' },
    header: { background: '#ffffff', text: '#000000' },
    navAlt: { background: '#ffffff', backgroundHeader: '#fafafa' },
    navBottom: { background: '#0f181f' },
    background: {
      paper: '#ffffff',
      paperLight: '#fafafa',
      nav: '#ffffff',
      navLight: '#ffffff',
      default: '#fafafa',
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
          scrollbarColor: '#c6c6c6 #c6c6c6',
        },
        '*::-webkit-scrollbar': {
          width: 12,
        },
        '*::-webkit-scrollbar-track': {
          background: '#c6c6c6',
        },
        '*::-webkit-scrollbar-thumb': {
          backgroundColor: '#f0f0f0',
          borderRadius: 20,
          border: '3px solid #f0f0f0',
        },
        html: {
          WebkitFontSmoothing: 'auto',
        },
        a: {
          color: '#507bc8',
        },
      },
    },
  },
};
