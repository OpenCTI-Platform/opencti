import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import AssociatedEntityField, { AssociatedEntityOption } from '@components/common/form/AssociatedEntityField';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import DialogActions from '@mui/material/DialogActions';
import { Formik } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';

type FileImportMarkingSelectionPopupProps = {
  closePopup: () => void;
  handleUpload: (fileMarkings: string[], associatedEntityId?: string) => void;
  isOpen: boolean;
  entityId?: string;
};

export type SubmittedFormValues = {
  fileMarkings: FieldOption[];
  associatedEntity: AssociatedEntityOption;
};

const FileImportMarkingSelectionPopup = ({ closePopup, handleUpload, isOpen, entityId }: FileImportMarkingSelectionPopupProps) => {
  const { t_i18n } = useFormatter();
  const handleSubmit = (values: SubmittedFormValues) => {
    const fileMarkings = values.fileMarkings.map(({ value }) => value);
    const associatedEntity = (entityId || values.associatedEntity?.value) || undefined; // Double check this logic
    closePopup();
    handleUpload(fileMarkings, associatedEntity);
  };

  return (
    <>
      <Formik
        enableReinitialize={true}
        initialValues={{
          fileMarkings: [],
          associatedEntity: { label: '', value: '', type: '' },
        }}
        onSubmit={handleSubmit}
      >
        {({ resetForm, submitForm, setFieldValue }) => (
          <Dialog
            open={isOpen}
            onClose={() => {
              resetForm();
              closePopup();
            }}
            title={t_i18n('Select file marking definitions')}
          >
            <ObjectMarkingField
              name="fileMarkings"
              label={t_i18n('File marking definition levels')}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              required={false}
            />
            {!entityId
              && (
                <div style={{ paddingTop: '10px' }}>
                  <AssociatedEntityField
                    label={t_i18n('Associated entity')}
                    name="associatedEntity"
                    onChange={setFieldValue}
                  />
                </div>
              )}
            <DialogActions>
              <Button
                variant="secondary"
                onClick={() => {
                  resetForm();
                  closePopup();
                }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
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
