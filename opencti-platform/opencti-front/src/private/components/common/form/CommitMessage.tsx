import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import type { ExternalReferencesValues } from './ExternalReferencesField';
import { ExternalReferencesField } from './ExternalReferencesField';
import { BYPASSREFERENCE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const useStyles = makeStyles(() => ({
  flex: {
    marginTop: 20,
    display: 'inline-flex',
    justifyContent: 'space-between',
    width: '100%',
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
  const { t } = useFormatter();
  const classes = useStyles();
  const [controlOpen, setControlOpen] = useState<boolean>(open ?? false);
  const handleOpen = () => setControlOpen(true);
  const handleControlClose = () => setControlOpen(false);

  const validateReferences = (
    references: ExternalReferencesValues | undefined,
  ) => !!references && references.length > 0;

  return (
    <div>
      {!handleClose && (
        <div className={classes.flex}>
          <Security needs={[BYPASSREFERENCE]}>
            <Button
              variant="outlined"
              color="primary"
              onClick={submitForm}
              disabled={disabled}
            >
              {t('Direct Update')}
            </Button>
          </Security>
          <Button
            variant="contained"
            color="primary"
            onClick={handleOpen}
            disabled={disabled}
          >
            {t('Update')}
          </Button>
        </div>
      )}
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={handleClose ? open : controlOpen}
        onClose={handleClose ?? handleControlClose}
        fullWidth={true}
      >
        <DialogTitle>{t('Reference modification')}</DialogTitle>
        <DialogContent>
          <ExternalReferencesField
            name="references"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values}
            id={id}
            noStoreUpdate={noStoreUpdate}
          />
          <Field
            component={MarkDownField}
            name="message"
            label={t('Message')}
            fullWidth={true}
            multiline={true}
            rows="2"
            style={{ marginTop: 20 }}
          />
        </DialogContent>
        <DialogActions>
          <Button
            color="primary"
            onClick={submitForm}
            disabled={disabled || !validateReferences(values)}
          >
            {t('Validate')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default CommitMessage;
