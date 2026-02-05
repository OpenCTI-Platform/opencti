import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import DialogActions from '@mui/material/DialogActions';
import makeStyles from '@mui/styles/makeStyles';
import { Field } from 'formik';
import { FunctionComponent, useState } from 'react';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import type { ExternalReferencesValues } from './ExternalReferencesField';
import { ExternalReferencesField } from './ExternalReferencesField';

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
    shouldValidate?: boolean | undefined,
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
              onClick={submitForm} // directly submit
              disabled={disabled}
              classes={{ root: classes.button }}
            >
              {t_i18n('Update without references')}
            </Button>
          </Security>
          <Button
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
        open={handleClose ? open : controlOpen}
        onClose={handleClose ?? handleCloseControl}
        title={t_i18n('Reference modification')}
      >
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
        <DialogActions>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE]}>
            <Button
              variant="secondary"
              onClick={submitForm} // directly submit
              disabled={disabled || validateReferences(values)}
            >
              {t_i18n('Update without references')}
            </Button>
          </Security>
          <Button
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
