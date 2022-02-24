export default (
  logo = null,
  primary = null,
  primaryAccent = null,
  secondary = null,
  background = null,
  paper = null,
  nav = null,
) => ({
  logo: logo || `${window.BASE_PATH}/static/logo_text.png`,
  palette: {
    mode: 'dark',
    primary: { main: primary || '#007fff' },
    secondary: { main: secondary || '#ec407a' },
    background: {
      default: background || '#ffffff',
      paper: paper || '#f3f6f9',
      nav: nav || '#f8fafd',
    },
  },
  typography: {
    fontFamily: '"IBM Plex Sans", sans-serif',
    body2: {
      fontSize: '0.8rem',
    },
    body1: {
      fontSize: '0.9rem',
    },
    overline: {
      fontWeight: 500,
    },
    h1: {
      margin: '0 0 10px 0',
      padding: 0,
      color: primary || '#007fff',
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
      color: primary || '#007fff',
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
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          scrollbarColor: '#6b6b6b #2b2b2b',
          '&::-webkit-scrollbar, & *::-webkit-scrollbar': {
            backgroundColor: paper || '#001e3c',
          },
          '&::-webkit-scrollbar-thumb, & *::-webkit-scrollbar-thumb': {
            borderRadius: 8,
            backgroundColor: primaryAccent || '#01478dff',
            minHeight: 24,
            border: '3px solid #001e3c',
          },
          '&::-webkit-scrollbar-thumb:focus, & *::-webkit-scrollbar-thumb:focus':
            {
              backgroundColor: primaryAccent || '#01478dff',
            },
          '&::-webkit-scrollbar-thumb:active, & *::-webkit-scrollbar-thumb:active':
            {
              backgroundColor: primaryAccent || '#01478dff',
            },
          '&::-webkit-scrollbar-thumb:hover, & *::-webkit-scrollbar-thumb:hover':
            {
              backgroundColor: primaryAccent || '#01478dff',
            },
          '&::-webkit-scrollbar-corner, & *::-webkit-scrollbar-corner': {
            backgroundColor: primaryAccent || '#01478dff',
          },
          html: {
            WebkitFontSmoothing: 'auto',
          },
          a: {
            color: primary || '#00b1ff',
          },
          'input:-webkit-autofill': {
            WebkitAnimation: 'autofill 0s forwards',
            animation: 'autofill 0s forwards',
            WebkitTextFillColor: '#ffffff !important',
            caretColor: 'transparent !important',
            WebkitBoxShadow:
              '0 0 0 1000px rgba(4, 8, 17, 0.88) inset !important',
            borderTopLeftRadius: 'inherit',
            borderTopRightRadius: 'inherit',
          },
          pre: {
            color: '#ffffff !important',
            background: `${primaryAccent || '#01478dff'} !important`,
          },
          code: {
            color: '#ffffff !important',
            background: `${primaryAccent || '#01478dff'} !important`,
          },
          '.react-mde': {
            border: '0 !important',
          },
          '.error .react-mde textarea': {
            border: '0 !important',
            borderBottom: '2px solid #f44336 !important',
            '&:hover': {
              border: '0 !important',
              borderBottom: '2px solid #f44336 !important',
            },
            '&:focus': {
              border: '0 !important',
              borderBottom: '2px solid #f44336 !important',
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
            background: 'transparent',
            borderBottom: '1px solid #b9bfc1 !important',
            transition: 'borderBottom .3s',
            '&:hover': {
              borderBottom: '2px solid #ffffff !important',
            },
            '&:focus': {
              borderBottom: `2px solid #${primary || '00b1ff'} !important`,
            },
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
          '.leaflet-container': {
            backgroundColor: '#0a1929 !important',
          },
        },
      },
    },
  },
});
