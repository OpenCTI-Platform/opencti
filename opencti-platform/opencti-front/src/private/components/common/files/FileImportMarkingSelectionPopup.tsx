import { Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import React from 'react';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import Button from '@mui/material/Button';
import { Option } from '@components/common/form/ReferenceField';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

type FileImportMarkingSelectionPopupProps = {
  closePopup: () => void;
  handleUpload: (fileMarkings: string[]) => void;
  isOpen: boolean
};

export type SubmittedMarkingsType = {
  fileMarkings: Option[];
};

const FileImportMarkingSelectionPopup = ({ closePopup, handleUpload, isOpen }: FileImportMarkingSelectionPopupProps) => {
  const { t_i18n } = useFormatter();

  const handleSubmit = (values: SubmittedMarkingsType) => {
    const fileMarkings = values.fileMarkings.map(({ value }) => value);
    closePopup();
    handleUpload(fileMarkings);
  };

  return (
    <>
      <Formik
        enableReinitialize={true}
        initialValues={{
          fileMarkings: [],
        }}
        onSubmit={handleSubmit}
      >
        {({ resetForm, submitForm, setFieldValue }) => (
          <Dialog open={isOpen} fullWidth={true} PaperProps={{ elevation: 1 }} onClose={() => {
            resetForm();
            closePopup();
          }}
          >
            <DialogTitle>{t_i18n('Select file marking definitions')}</DialogTitle>
            <DialogContent>
              <ObjectMarkingField
                name="fileMarkings"
                label={t_i18n('File marking definition levels')}
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
            </DialogContent>
            <DialogActions>
              <Button onClick={() => {
                resetForm();
                closePopup();
              }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={submitForm}
              >
                {t_i18n('Validate')}
              </Button>
            </DialogActions>
          </Dialog>
        )}
      </Formik>
    </>
  );
};

export default FileImportMarkingSelectionPopup;
