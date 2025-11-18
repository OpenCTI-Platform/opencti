import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import type { ExternalReferencesValues } from './ExternalReferencesField';
import { ExternalReferencesField } from './ExternalReferencesField';
import { KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: 10,
  },
}));

interface CommitMessageProps {
  id: string;
  submitForm: () => Promise<void>;
  disabled: boolean;
  setFieldValue: (
    field: string,
    value: ExternalReferencesValues,
    shouldValidate?: boolean | undefined
  ) => void;
  values: ExternalReferencesValues | undefined;
  noStoreUpdate?: boolean;
  open: boolean;
  handleClose?: () => void;
}

const CommitMessage: FunctionComponent<CommitMessageProps> = ({
  id,
  submitForm,
  disabled,
  setFieldValue,
  values,
  open,
  noStoreUpdate,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [controlOpen, setControlOpen] = useState<boolean>(open ?? false);
  const handleOpenControl = () => setControlOpen(true);
  const handleCloseControl = () => setControlOpen(false);
  const validateReferences = (
    references: ExternalReferencesValues | undefined,
  ) => !!references && references.length > 0;
  const onSubmitFromDialog = async () => {
    await submitForm();
    handleClose?.();
    handleCloseControl(); // make sure the dialog is closed now
  };

  // 2 behaviors possible
  // - "normal" behavior --> open a dialog with a ref selector and a commit message
  // - KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE capa is defined --> user is able to bypass the ref selection + commit message, no dialog

  return (
    <>
      {!handleClose && (
        <div className={classes.buttons}>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE]}>
            <Button
              variant="contained"
              color="warning"
              onClick={submitForm} // directly submit
              disabled={disabled}
              classes={{ root: classes.button }}
            >
              {t_i18n('Update without references')}
            </Button>
          </Security>
          <Button
            variant="contained"
            color="primary"
            onClick={handleOpenControl}
            disabled={disabled}
            classes={{ root: classes.button }}
          >
            {t_i18n('Update')}
          </Button>
        </div>
      )}
      <Dialog
        data-testid="commit-message-page"
        slotProps={{ paper: { elevation: 1 } }}
        open={handleClose ? open : controlOpen}
        onClose={handleClose ?? handleCloseControl}
        fullWidth
      >
        <DialogTitle>{t_i18n('Reference modification')}</DialogTitle>
        <DialogContent>
          <ExternalReferencesField
            name="references"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values}
            id={id}
            noStoreUpdate={noStoreUpdate}
            required={false}
          />
          <Field
            component={MarkdownField}
            name="message"
            label={t_i18n('Message')}
            fullWidth
            multiline
            rows="2"
            style={{ marginTop: 20 }}
          />
        </DialogContent>
        <DialogActions>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE]}>
            <Button
              color="warning"
              onClick={submitForm} // directly submit
              disabled={disabled || validateReferences(values)}
              classes={{ root: classes.button }}
            >
              {t_i18n('Update without references')}
            </Button>
          </Security>
          <Button
            color="primary"
            onClick={onSubmitFromDialog}
            disabled={disabled || !validateReferences(values)}
          >
            {t_i18n('Validate')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default CommitMessage;
