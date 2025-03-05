import React, { useEffect, useState } from 'react';
import Snackbar from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';
import { head } from 'ramda';
import { MESSAGING$ } from '../relay/environment';
import { useFormatter } from './i18n';

const Message = () => {
  const [open, setOpen] = useState(false);
  const [type, setType] = useState('message');
  const [text, setText] = useState('');

  const { t_i18n } = useFormatter();

  useEffect(() => {
    const subscription = MESSAGING$.messages.subscribe({
      next: (messages) => {
        const firstMessage = head(messages);
        if (firstMessage) {
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
  });

  const handleCloseMessage = (reason) => {
    if (reason === 'clickaway') return;
    setOpen(false);
  };

  const displayAlert = () => {
    switch (type) {
      case 'error':
        return <Alert severity="error" onClose={handleCloseMessage}>
          {text}
        </Alert>;
      case 'nlq':
        return <Alert severity="info" onClose={handleCloseMessage}>
          {text}
        </Alert>;
      default:
        return <Alert
          severity="success"
          onClose={handleCloseMessage}
               >
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
