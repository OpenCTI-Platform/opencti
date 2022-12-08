export default (logo = null, primary = null, secondary = null) => ({
  fontFamily: 'DINNextLTPro-Light, sans-serif',
  logo: logo || `${window.BASE_PATH}/static/Darklight-Logo.png`,
  waterMark: `${window.BASE_PATH}/static/DarkLight_CyioLogo-Lock-Up.png`,
  palette: {
    type: 'dark',
    text: { secondary: 'rgba(255, 255, 255, 0.5)' },
    primary: { main: primary || '#075AD3' },
    secondary: { main: secondary || '#F9B406' },
    header: { background: '#06102D', text: '#ffffff' },
    navAlt: {
      background: '#075AD3',
      backgroundHeader: '#2d5161',
      backgroundHeaderText: '#ffffff',
    },
    navBottom: { background: '#0f181f' },
    background: {
      paper: '#1F2842',
      paperLight: '#2d5161',
      nav: '#075AD3',
      navLight: '#14262c',
      default: '#06102D',
      chip: 'rgba(64, 193, 255, 0.2)',
      line: 'rgba(64, 193, 255, 0.05)',
    },
    action: { disabled: '#4f4f4f', grid: '#0f181f', expansion: '#193e45' },
    divider: 'rgba(255, 255, 255, 0.2)',
    riskPriority: {
      veryHigh: '#FC0D1B',
      high: '#F35426',
      moderate: '#E28120',
      low: '#FFA800',
      veryLow: '#FCC434',
    },
    dataView: {
      selectedBackgroundColor: 'linear-gradient(0deg, rgba(0, 0, 0, 0.5), rgba(0, 0, 0, 0.5)),#075AD3 !important',
      selectedBorder: '#075AD3',
      border: '#1F2842',
    },
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
      color: primary || '#fff',
      fontWeight: 400,
      fontSize: 22,
    },
    h2: {
      margin: '0 0 10px 0',
      padding: 0,
      fontWeight: 500,
      fontSize: 16,
      textTransform: 'uppercase',
    },
    h3: {
      margin: '0 0 10px 0',
      padding: 0,
      color: primary || '#00bcd4',
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
      fontWeight: 400,
      fontSize: 13,
      textTransform: 'uppercase',
      marginTop: -4,
    },
    h6: {
      fontWeight: 400,
      fontSize: 18,
    },
  },
  overrides: {
    MuiButton: {
      containedPrimary: {
        color: '#fff',
      },
      containedSecondary: {
        color: '#06102D',
      },
    },
    MuiCssBaseline: {
      '@global': {
        '*': {
          scrollbarColor: '#14262c #2d4b5b',
        },
        '*::-webkit-scrollbar': {
          width: 8,
        },
        '*::-webkit-scrollbar-track': {
          // background: '#2d4b5b',
          background: 'transparent',
          borderRadius: '7px',
        },
        '*::-webkit-scrollbar-thumb': {
          // backgroundColor: '#14262c',
          // borderRadius: 20,
          // border: '3px solid #2d4b5b',
          borderRadius: '7px',
          backgroundColor: 'rgba(241, 241, 242, 0.35)',
          border: 'none',

        },
        html: {
          WebkitFontSmoothing: 'auto',
        },
        a: {
          color: primary || '#00bcd4',
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
          background: '#2d5161',
        },
        code: {
          background: '#2b6779',
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
        '.react-grid-placeholder': {
          backgroundColor: 'rgba(0, 188, 212, 0.8) !important',
        },
        '.react_time_range__track': {
          backgroundColor: 'rgba(1, 226, 255, 0.1) !important',
          borderLeft: '1px solid #00bcd4 !important',
          borderRight: '1px solid #00bcd4 !important',
        },
        '.react_time_range__handle_marker': {
          backgroundColor: '#00bcd4 !important',
        },
      },
    },
  },
});
