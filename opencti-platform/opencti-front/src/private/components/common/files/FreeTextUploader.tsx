import React, { useState } from 'react';
import { graphql } from 'react-relay';
import IconButton, { type IconButtonOwnProps } from '@mui/material/IconButton';
import { TextFieldsOutlined } from '@mui/icons-material';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import Tooltip from '@mui/material/Tooltip';
import { Field, Formik, FormikHelpers } from 'formik';
import DialogTitle from '@mui/material/DialogTitle';
import * as Yup from 'yup';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { now } from '../../../../utils/Time';
import { isValidStixBundle } from '../../../../utils/String';
import { KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

const freeTextUploaderGlobalMutation = graphql`
  mutation FreeTextUploaderGlobalMutation($file: Upload!, $fileMarkings: [String]) {
    uploadImport(file: $file, fileMarkings: $fileMarkings) {
      ...FileLine_file
    }
  }
`;

const freeTextUploaderEntityMutation = graphql`
  mutation FreeTextUploaderEntityMutation($id: ID!, $file: Upload!, $fileMarkings: [String]) {
    stixCoreObjectEdit(id: $id) {
      importPush(file: $file, fileMarkings: $fileMarkings) {
        ...FileLine_file
      }
    }
  }
`;

const freeTextValidation = (t: (arg: string) => string) => Yup.object().shape({
  content: Yup.string().required(t('This field is required')),
});

type FreeTextUploaderType = {
  color?: IconButtonOwnProps['color'];
  entityId?: string;
  onUploadSuccess: () => void;
  size?: IconButtonOwnProps['size'];
};

type SubmittedValuesType = {
  content: string;
  fileMarkings: FieldOption[];
};

const FreeTextUploader = ({ color, entityId, onUploadSuccess, size }: FreeTextUploaderType) => {
  const [isOpen, setIsOpen] = useState<boolean>(false);

  const { t_i18n } = useFormatter();

  const handleOpen = () => setIsOpen(true);

  const handleClose = () => setIsOpen(false);

  const handleSubmit = (
    { content, fileMarkings }: SubmittedValuesType,
    { resetForm, setSubmitting }: FormikHelpers<SubmittedValuesType>,
  ) => {
    let file;
    if (isValidStixBundle(content)) {
      const blob = new Blob([content], { type: 'text/json' });
      file = new File(
        [blob],
        `${now()}_${entityId ?? 'global'}.json`,
        {
          type: 'application/json',
        },
      ) as File;
    } else {
      const blob = new Blob([content], { type: 'text/plain' });
      file = new File(
        [blob],
        `${now()}_${entityId ?? 'global'}.txt`,
        {
          type: 'text/plain',
        },
      );
    }

    const fileMarkingIds = fileMarkings.map(({ value }) => value);

    commitMutation({
      mutation: entityId
        ? freeTextUploaderEntityMutation
        : freeTextUploaderGlobalMutation,
      variables: {
        file,
        fileMarkings: fileMarkingIds,
        id: entityId,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
        MESSAGING$.notifySuccess('File successfully uploaded');
        onUploadSuccess();
      },
      optimisticUpdater: undefined,
      updater: undefined,
      optimisticResponse: undefined,
      onError: () => setIsOpen(false),
      setSubmitting: undefined,
    });
  };

  return (
    <Security needs={[KNOWLEDGE_KNUPLOAD]}>
      <>
        <Tooltip title={t_i18n('Copy/paste text content')}>
          <IconButton
            color={color || 'primary'}
            onClick={handleOpen}
            size={size || 'large'}
          >
            <TextFieldsOutlined />
          </IconButton>
        </Tooltip>
        <Formik<SubmittedValuesType>
          enableReinitialize={true}
          initialValues={{
            content: '',
            fileMarkings: [],
          }}
          onSubmit={handleSubmit}
          validationSchema={freeTextValidation(t_i18n)}
        >
          {({ handleReset, isSubmitting, setFieldValue, submitForm }) => (
            <Dialog
              fullWidth={true}
              onClose={handleClose}
              open={isOpen}
              slotProps={{ paper: { elevation: 1 } }}
            >
              <DialogTitle>{t_i18n('Free text import')}</DialogTitle>
              <DialogContent>
                <Field
                  component={TextField}
                  fullWidth={true}
                  label={t_i18n('Content')}
                  multiline={true}
                  name="content"
                  rows="8"
                  variant="standard"
                />
                <ObjectMarkingField
                  label={t_i18n('File marking definition levels')}
                  name="fileMarkings"
                  style={fieldSpacingContainerStyle}
                  onChange={() => {
                  }}
                  setFieldValue={setFieldValue}
                  required={false}
                />
              </DialogContent>
              <DialogActions>
                <Button
                  variant="secondary"
                  disabled={isSubmitting}
                  onClick={() => {
                    handleReset();
                    handleClose();
                  }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  disabled={isSubmitting}
                  onClick={submitForm}
                >
                  {t_i18n('Import')}
                </Button>
              </DialogActions>
            </Dialog>
          )}
        </Formik>
      </>
    </Security>
  );
};

export default FreeTextUploader;
