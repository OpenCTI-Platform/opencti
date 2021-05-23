export default {
  fontFamily: 'Roboto, sans-serif',
  palette: {
    type: 'dark',
    text: { secondary: 'rgba(255, 255, 255, 0.5)' },
    primary: { main: '#00bcd4' },
    secondary: { main: '#ff3d00' },
    header: { background: '#1b2226', text: '#ffffff' },
    navAlt: {
      background: '#14262c',
      backgroundHeader: '#2d4b5b',
      backgroundHeaderText: '#ffffff',
    },
    navBottom: { background: '#0f181f' },
    background: {
      paper: '#28353a',
      paperLight: '#265058',
      nav: '#28353a',
      navLight: '#14262c',
      default: '#222c30',
      chip: 'rgba(64, 193, 255, 0.2)',
    },
    action: { disabled: '#4f4f4f', grid: '#0f181f' },
    divider: 'rgba(255, 255, 255, 0.2)',
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
      color: '#00bcd4',
      fontWeight: 400,
      fontSize: 22,
    },
    h2: {
      margin: '0 0 10px 0',
      padding: 0,
      color: '#ffffff',
      fontWeight: 500,
      fontSize: 16,
      textTransform: 'uppercase',
    },
    h3: {
      margin: '0 0 10px 0',
      padding: 0,
      color: '#00bcd4',
      fontWeight: 400,
      fontSize: 13,
    },
    h4: {
      margin: '0 0 10px 0',
      padding: 0,
      textTransform: 'uppercase',
      fontSize: 12,
      fontWeight: 500,
      color: '#a8a8a8',
    },
    h5: {
      color: '#ffffff',
      fontWeight: 400,
      fontSize: 13,
      textTransform: 'uppercase',
      marginTop: -4,
    },
    h6: {
      color: '#ffffff',
      fontWeight: 400,
      fontSize: 18,
    },
  },
  overrides: {
    MuiCssBaseline: {
      '@global': {
        '*': {
          scrollbarColor: '#14262c #2d4b5b',
        },
        '*::-webkit-scrollbar': {
          width: 12,
        },
        '*::-webkit-scrollbar-track': {
          background: '#2d4b5b',
        },
        '*::-webkit-scrollbar-thumb': {
          backgroundColor: '#14262c',
          borderRadius: 0,
          border: '3px solid #14262c',
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
          '-webkit-text-fill-color': '#ffffff !important',
          caretColor: 'transparent !important',
          '-webkit-box-shadow':
            '0 0 0 1000px rgba(4, 8, 17, 0.88) inset !important',
          borderTopLeftRadius: 'inherit',
          borderTopRightRadius: 'inherit',
        },
        pre: {
          background: 'rgba(64, 193, 255, 0.2)',
        },
        code: {
          background: 'rgba(64, 193, 255, 0.2)',
        },
        '.react-mde': {
          border: '0 !important',
          borderBottom: '1px solid #b9bfc1 !important',
          '&:hover': {
            borderBottom: '2px solid #ffffff !important',
            marginBottom: '-1px !important',
          },
        },
        '.error .react-mde': {
          border: '0 !important',
          borderBottom: '2px solid #f44336 !important',
          marginBottom: '-1px !important',
          '&:hover': {
            border: '0 !important',
            borderBottom: '2px solid #f44336 !important',
            marginBottom: '-1px !important',
          },
        },
        '.mde-header': {
          border: '0 !important',
          backgroundColor: 'transparent !important',
          color: '#ffffff !important',
        },
        '.mde-header-item button': {
          color: '#ffffff !important',
        },
        '.mde-tabs button': {
          color: '#ffffff !important',
        },
        '.mde-textarea-wrapper textarea': {
          color: '#ffffff',
          backgroundColor: '#14262c',
        },
      },
    },
  },
};
