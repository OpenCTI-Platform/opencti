import React, { ReactElement, useEffect, useState } from 'react';
import Snackbar, { SnackbarCloseReason } from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';
import { AutoAwesomeOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import { MESSAGING$ } from '../relay/environment';
import { useFormatter } from './i18n';
import type { Theme } from './Theme';

const Message = () => {
  const [open, setOpen] = useState(false);
  const [type, setType] = useState('message');
  const [text, setText] = useState<string | ReactElement>('');

  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  useEffect(() => {
    const subscription = MESSAGING$.messages.subscribe({
      next: (messages) => {
        if (messages && messages.length > 0 && messages[0]) {
          const firstMessage = messages[0] as { text: string | ReactElement, type: string };
          const translatedText = firstMessage.text instanceof String
            ? t_i18n(firstMessage.text)
            : firstMessage.text;
          setOpen(true);
          setType(firstMessage.type);
          setText(translatedText);
        }
      },
    });
    return () => {
      subscription.unsubscribe();
    };
  }, []);

  const handleCloseMessage = (reason?: SnackbarCloseReason) => {
    if (reason === 'clickaway') return;
    setOpen(false);
  };

  const displayAlert = () => {
    switch (type) {
      case 'error':
        return <Alert severity="error" onClose={() => handleCloseMessage()}>
          {text}
        </Alert>;
      case 'nlq':
        return <Alert
          icon={<AutoAwesomeOutlined fontSize="small" style={{ color: theme.palette.ai.main }} />}
          style={{ backgroundColor: theme.palette.ai.background, color: theme.palette.ai.light }}
          onClose={() => handleCloseMessage()}
               >
          {text}
        </Alert>;
      case 'message':
        return <Alert severity="success" onClose={() => handleCloseMessage()}>
          {text}
        </Alert>;
      default:
        return <Alert severity="success" onClose={() => handleCloseMessage()}>
          {text}
        </Alert>;
    }
  };

  return (
    <Snackbar
      anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      open={open}
      onClose={(_, reason) => handleCloseMessage(reason)}
      autoHideDuration={type === 'message' ? 4000 : 8000}
    >
      {displayAlert()}
    </Snackbar>
  );
};

export default Message;
