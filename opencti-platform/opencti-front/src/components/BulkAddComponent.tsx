import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React, { useEffect } from 'react';
import { Field } from 'formik';
import Alert from '@mui/material/Alert';
import { useFormatter } from './i18n';
import TextField from './TextField';

type BulkAddComponentProps = {
  openBulkModal: boolean
  bulkValueFieldValue: string
  handleCloseBulkModal: (val: string) => void
  localHandleCancelClearBulkModal: () => void
};

const BulkAddComponent: React.FC<BulkAddComponentProps> = ({
  openBulkModal,
  bulkValueFieldValue,
  handleCloseBulkModal,
  localHandleCancelClearBulkModal,
}) => {
  const { t_i18n } = useFormatter();
  const [localBulkValueField, setLocalBulkValueField] = React.useState('');
  const [warningVisible, setWarningVisible] = React.useState(false);

  function monitorBulkValue(value: string) {
    const observable_lines = value.split('\n');
    // 50 lines have been entered based on \n newlines - warn user and remove Continue button.
    if (observable_lines.length >= 51 !== warningVisible) {
      setWarningVisible(observable_lines.length >= 51);
    }
  }
  useEffect(() => {
    setLocalBulkValueField(bulkValueFieldValue);
  }, [bulkValueFieldValue]);
  return (
    <React.Fragment>
      <Dialog
        PaperProps={{ elevation: 3 }}
        open={openBulkModal}
        fullWidth={true}
        onClose={localHandleCancelClearBulkModal}
      >
        <DialogTitle>{t_i18n('Add Multiple Observable Values')}</DialogTitle>
        <DialogContent style={{ marginTop: 0, paddingTop: 0 }}>
          <Typography style={{ whiteSpace: 'pre-line', paddingBottom: '20px', fontSize: '13px' }}>
            {t_i18n('Enter one observable per line. Observables must be the same type.')}
            <br/>
            {t_i18n('If you are adding more than 50 values, please upload them through')} <a href='/dashboard/data/import'>{t_i18n('Imports')}</a>.
          </Typography>
          <Field
            component={TextField}
            label={t_i18n('Multiple Values')}
            variant="outlined"
            value={localBulkValueField}
            name="bulk_value_field"
            fullWidth={true}
            multiline={true}
            rows="5"
            onChange={(name: string, value: string) => { setLocalBulkValueField(value); monitorBulkValue(value); }}
          />
          {warningVisible
            && (<Alert severity="warning">{t_i18n('Remove values or please upload them through')} <a href='/dashboard/data/import'>{t_i18n('Imports')}</a>.</Alert>)}
          <DialogActions>
            <Button onClick={localHandleCancelClearBulkModal}>
              {t_i18n('Cancel')}
            </Button>
            <Button color="secondary" disabled={warningVisible} onClick={() => handleCloseBulkModal(localBulkValueField)}>
              {t_i18n('Continue')}
            </Button>
          </DialogActions>
        </DialogContent>
      </Dialog>
    </React.Fragment>
  );
};

export default BulkAddComponent;
