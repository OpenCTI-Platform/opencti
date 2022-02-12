export default (logo = null, primary = null, secondary = null) => ({
  fontFamily: 'Roboto, sans-serif',
  logo: logo || `${window.BASE_PATH}/static/logo_text.png`,
  palette: {
    mode: 'light',
    text: { secondary: 'rgba(0, 0, 0, 0.5)' },
    primary: { main: primary || '#507bc8' },
    secondary: { main: secondary || '#d84315' },
    header: { background: primary || '#507bc8', text: '#ffffff' },
    navAlt: {
      background: '#ffffff',
      backgroundHeader: primary || '#507bc8',
      backgroundHeaderText: '#ffffff',
    },
    navBottom: { background: '#ffffff' },
    background: {
      paper: '#ffffff',
      paperLight: '#f5f5f5',
      nav: '#ffffff',
      navLight: '#ffffff',
      default: '#f5f5f5',
      chip: 'rgba(80, 123, 200, 0.6)',
      line: 'rgba(80, 123, 200, 0.05)',
    },
    action: { disabled: '#ababab', grid: '#dbdbdb', expansion: '#fafafa' },
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
      color: primary || '#507bc8',
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
      color: primary || '#507bc8',
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
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        '@global': {
          '*': {
            scrollbarColor: '#c6c6c6 #f0f0f0',
          },
          '*::-webkit-scrollbar': {
            width: 12,
          },
          '*::-webkit-scrollbar-track': {
            background: '#f0f0f0',
          },
          '*::-webkit-scrollbar-thumb': {
            backgroundColor: '#c6c6c6',
            borderRadius: 20,
            border: '3px solid #f0f0f0',
          },
          html: {
            WebkitFontSmoothing: 'auto',
          },
          a: {
            color: primary || '#507bc8',
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
          '.react-mde': {
            border: '0 !important',
            borderBottom: '1px solid #aaaaaa !important',
            '&:hover': {
              borderBottom: '2px solid #000000 !important',
              marginBottom: '-1px !important',
            },
          },
          '.error .react-mde': {
            border: '0 !important',
            borderBottom: '2px solid #f44336 !important',
            marginBottom: '-1px !important',
            ':&hover': {
              border: '0 !important',
              borderBottom: '2px solid #f44336 !important',
              marginBottom: '-1px !important',
            },
          },
          '.mde-header': {
            border: '1px solid #e6e6e6 !important',
            backgroundColor: '#fafafa !important',
            color: '#000000 !important',
          },
          '.mde-header-item button': {
            color: '#000000 !important',
          },
          '.mde-tabs button': {
            color: '#000000 !important',
          },
          '.mde-textarea-wrapper textarea': {
            color: '#000000',
            backgroundColor: '#ffffff',
          },
          '.react-grid-placeholder': {
            backgroundColor: 'rgba(80, 123, 200, 0.8) !important',
          },
          '.react_time_range__track': {
            backgroundColor: 'rgba(80, 123, 200, 0.1) !important',
            borderLeft: '1px solid #507bc8 !important',
            borderRight: '1px solid #507bc8 !important',
          },
          '.react_time_range__handle_marker': {
            backgroundColor: '#507bc8 !important',
          },
        },
      },
    },
  },
});
