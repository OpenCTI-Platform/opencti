import React, { useEffect, useState } from 'react';
import Snackbar from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import { Form, Formik } from 'formik';
import { MESSAGING$ } from '../relay/environment';
import { useFormatter } from './i18n';
import RequestAccessDialog from './RequestAccessDialog';
import useHelper from '../utils/hooks/useHelper';

const Message = () => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState(false);
  const [fullError, setFullError] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [text, setText] = useState('');

  let isRequestAccessFeatureEnabled = false;
  try {
    // FIXME find why it's breaking GraphIQL
    const { isRequestAccessEnabled, isFeatureEnable } = useHelper();
    isRequestAccessFeatureEnabled = isFeatureEnable('ORGA_SHARING_REQUEST_FF') && isRequestAccessEnabled();
  } catch (e) {
    // When called from public, no useAuth()
  }

  useEffect(() => {
    const subscription = MESSAGING$.messages.subscribe({
      next: (messages) => {
        const firstMessage = messages[0];
        if (firstMessage) {
          const firstMessageText = firstMessage.text instanceof String
            ? t_i18n(firstMessage.text)
            : firstMessage.text;
          const firstMessageError = firstMessage.type === 'error';
          setOpen(true);
          setFullError(firstMessage.fullError || null);
          setError(firstMessageError);
          setText(firstMessageText);
        }
      },
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);

  const handleCloseMessage = (reason) => {
    if (reason === 'clickaway') return;
    setOpen(false);
  };

  const handleDialogClose = () => {
    setDialogOpen(false);
  };

  const handleDialogOpen = () => {
    setDialogOpen(true);
    setOpen(false);
  };
  const entityIds = fullError?.extensions?.data?.entityIds || [];

  return (
    <>
      <Snackbar
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
        open={open}
        onClose={handleCloseMessage}
        autoHideDuration={error ? 8000 : 4000}
        sx={{ display: 'flex', alignItems: 'center' }}
      >
        {/* eslint-disable-next-line no-nested-ternary */}
        {fullError?.extensions?.code === 'ACCESS_REQUIRED' ? (
          <Alert
            severity="error"
            style={{ display: 'flex', alignItems: 'center' }}
            onClose={handleCloseMessage}
          >
            <div style={{ display: 'flex', alignItems: 'center' }}>
              {text}
              {fullError && (
                <Formik>
                  <Form>
                    <Button
                      variant="outlined"
                      size="small"
                      color="error"
                      sx={{ marginLeft: 2 }}
                      onClick={handleDialogOpen}
                    >
                      Request Access
                    </Button>
                  </Form>
                </Formik>
              )}
            </div>
          </Alert>
        ) : error ? (
          <Alert severity="error" onClose={handleCloseMessage}>
            {text}
          </Alert>
        ) : (
          <Alert
            severity="success"
            onClose={handleCloseMessage}
          >
            {text}
          </Alert>
        )}
      </Snackbar>
      {isRequestAccessFeatureEnabled
        && <RequestAccessDialog
          open={dialogOpen}
          onClose={handleDialogClose}
          entitiesIds={entityIds}
           />
      }
    </>
  );
};

export default Message;
