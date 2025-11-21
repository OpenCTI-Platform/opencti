import React, { ReactElement, useEffect, useState } from 'react';
import Snackbar, { SnackbarCloseReason } from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';
import { LogoXtmOneIcon } from 'filigran-icon';
import { useTheme } from '@mui/styles';
import { Formik, Form } from 'formik';
import Button from '@mui/material/Button/Button';
import FiligranIcon from '@components/common/FiligranIcon';
import { MESSAGING$ } from '../relay/environment';
import { useFormatter } from './i18n';
import type { Theme } from './Theme';
import RequestAccessDialog from './RequestAccessDialog';
import useHelper from '../utils/hooks/useHelper';
import useEnterpriseEdition from '../utils/hooks/useEnterpriseEdition';

type FullError = {
  message?: string;
  extensions?: {
    code?: string;
    data?: {
      http_status?: number;
      genre?: string;
      entityIds?: string[];
    };
    stacktrace?: string[];
  };
};

const Message = () => {
  const [open, setOpen] = useState(false);
  const [type, setType] = useState('message');
  const [text, setText] = useState<string | ReactElement>('');
  const [_, setError] = useState(false);
  const [fullError, setFullError] = useState<FullError | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  let isEnterpriseEdition = false;
  let isRequestAccessFeatureEnabled = false;

  try {
    // if you move anything oustide of this try/catch, please check that /public/graphql is still working.
    isEnterpriseEdition = useEnterpriseEdition();
    const { isRequestAccessEnabled } = useHelper();
    isRequestAccessFeatureEnabled = isRequestAccessEnabled() && isEnterpriseEdition;
  } catch (_e) {
    // When called being unauthenticated there is no useAuth()
  }

  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  useEffect(() => {
    const subscription = MESSAGING$.messages.subscribe({
      next: (messages) => {
        if (messages && messages.length > 0 && messages[0]) {
          const firstMessage = messages[0] as { text: string | ReactElement, type: string, fullError: FullError | null };
          const textPart = firstMessage.text;
          const translatedText = (typeof textPart === 'string' || textPart instanceof String)
            ? t_i18n(textPart)
            : textPart;
          const firstMessageError = firstMessage.type === 'error';
          setOpen(true);
          setFullError(firstMessage.fullError || null);
          setError(firstMessageError);
          setText(translatedText);
          setType(firstMessage.type);
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

  const handleDialogClose = () => {
    setDialogOpen(false);
  };

  const handleDialogOpen = () => {
    if (!isEnterpriseEdition) {
      setText(t_i18n('You need to enable EE License to use this feature'));
      return;
    }
    setDialogOpen(true);
    setOpen(false);
  };

  const entityIds = fullError?.extensions?.data?.entityIds || [];

  const displayAlert = () => {
    if (isRequestAccessFeatureEnabled && fullError?.extensions?.code === 'ACCESS_REQUIRED') {
      return (
        <Alert
          severity="error"
          style={{ display: 'flex', alignItems: 'center' }}
          onClose={() => handleCloseMessage()}
        >
          <div style={{ display: 'flex', alignItems: 'center' }}>
            {text}
            <Formik initialValues={{}} onSubmit={() => {}}>
              <Form>
                <Button
                  variant="outlined"
                  size="small"
                  color="error"
                  sx={{ marginLeft: 2 }}
                  onClick={handleDialogOpen}
                >
                  {t_i18n('Request Access')}
                </Button>
              </Form>
            </Formik>
          </div>
        </Alert>
      );
    }
    switch (type) {
      case 'error':
        return <Alert severity="error" onClose={() => handleCloseMessage()}>
          {text}
        </Alert>;
      case 'nlq':
        return <Alert
          icon={<FiligranIcon icon={LogoXtmOneIcon} size='small' color="ai" />}
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
    <>
      <Snackbar
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
        open={open}
        onClose={(__, reason) => handleCloseMessage(reason)}
        autoHideDuration={type === 'message' ? 4000 : 8000}
      >
        {displayAlert()}
      </Snackbar>
      {isRequestAccessFeatureEnabled && (
      <RequestAccessDialog
        open={dialogOpen}
        onClose={handleDialogClose}
        entitiesIds={entityIds}
      />
      )}
    </>
  );
};

export default Message;
