import React, { ReactElement, useEffect, useState } from 'react';
import Snackbar, { SnackbarCloseReason } from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';
import { LogoXtmOneIcon } from 'filigran-icon';
import { useTheme } from '@mui/material/styles';
import { Formik, Form } from 'formik';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { Close } from '@mui/icons-material';
import FiligranIcon from '@components/common/FiligranIcon';
import { MESSAGING$, MessageAction } from '../relay/environment';
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

type MessageType = {
  text: string | ReactElement;
  type: string;
  fullError: FullError | null;
  action?: MessageAction;
};

const Message = () => {
  const [open, setOpen] = useState(false);
  const [type, setType] = useState('message');
  const [text, setText] = useState<string | ReactElement>('');
  const [_, setError] = useState(false);
  const [fullError, setFullError] = useState<FullError | null>(null);
  const [action, setAction] = useState<MessageAction | null>(null);
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
          const firstMessage = messages[0] as MessageType;
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
          setAction(firstMessage.action ?? null);
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

  const renderSuccessAlert = () => {
    if (!action) {
      return (
        <Alert severity="success" onClose={() => handleCloseMessage()}>
          {text}
        </Alert>
      );
    }
    // MUI drops its close button when an action is given, so both are rendered here
    return (
      <Alert
        severity="success"
        action={(
          <>
            <Button
              variant="tertiary"
              size="small"
              onClick={() => {
                action.onClick();
                handleCloseMessage();
              }}
            >
              {t_i18n(action.label)}
            </Button>
            <IconButton
              variant="tertiary"
              size="small"
              aria-label={t_i18n('Close')}
              onClick={() => handleCloseMessage()}
            >
              <Close fontSize="small" />
            </IconButton>
          </>
        )}
      >
        <span role="status">{text}</span>
      </Alert>
    );
  };

  // MUI pauses the auto-hide while the message is hovered or focused, so that its action can be reached
  const autoHideDuration = () => {
    if (action) return 8000;
    return type === 'message' ? 4000 : 8000;
  };

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
                  variant="tertiary"
                  size="small"
                  intent="destructive"
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
        return (
          <Alert severity="error" onClose={() => handleCloseMessage()}>
            {text}
          </Alert>
        );
      case 'warning':
        return (
          <Alert severity="warning" onClose={() => handleCloseMessage()}>
            {text}
          </Alert>
        );
      case 'nlq':
        return (
          <Alert
            icon={<FiligranIcon icon={LogoXtmOneIcon} size="small" style={{ color: theme.palette.ai.main }} />}
            style={{
              backgroundColor: theme.palette.ai.background,
              color: theme.palette.ai.light,
            }}
            onClose={() => handleCloseMessage()}
          >
            {text}
          </Alert>
        );
      case 'message':
      default:
        return renderSuccessAlert();
    }
  };

  return (
    <>
      <Snackbar
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
        open={open}
        onClose={(__, reason) => handleCloseMessage(reason)}
        autoHideDuration={autoHideDuration()}
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
