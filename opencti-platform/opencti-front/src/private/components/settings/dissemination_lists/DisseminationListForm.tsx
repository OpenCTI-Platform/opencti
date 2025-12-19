import React, { FunctionComponent } from 'react';
import { FormikHelpers } from 'formik/dist/types';
import { useTheme } from '@mui/styles';
import { Field, Formik } from 'formik';
import { disseminationListValidator } from '@components/settings/dissemination_lists/DisseminationListUtils';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { parseEmailList } from '../../../../utils/email';
import { MESSAGING$ } from '../../../../relay/environment';

export interface DisseminationListFormData {
  name: string;
  emails: string;
  description: string;
}

export type DisseminationListFormInputKeys = keyof DisseminationListFormData;

interface DisseminationListFormProps {
  onSubmit: (values: DisseminationListFormData, helpers: FormikHelpers<DisseminationListFormData>) => void;
  onSubmitField?: (field: DisseminationListFormInputKeys, value: string) => void;
  defaultValues?: DisseminationListFormData;
  onReset?: () => void;
}

const DisseminationListForm: FunctionComponent<DisseminationListFormProps> = ({
  onSubmit,
  onSubmitField,
  defaultValues,
  onReset,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const isEdition = !!defaultValues;
  const validation = disseminationListValidator(t_i18n);

  const initialValues: DisseminationListFormData = defaultValues ?? {
    name: '',
    emails: '',
    description: '',
  };

  const updateField = async (field: DisseminationListFormInputKeys, value: string) => {
    if (onSubmitField) {
      validation.validateAt(field, { [field]: value })
        .then(() => onSubmitField(field, value))
        .catch(() => false);
    }
  };

  const onUpdate = isEdition ? updateField : undefined;

  return (
    <Formik<DisseminationListFormData>
      initialValues={initialValues}
      enableReinitialize={true}
      validateOnBlur={isEdition}
      validateOnChange={isEdition}
      validationSchema={validation}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onSubmit={onUpdate}
            required
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            onSubmit={onUpdate}
            fullWidth={true}
            multiline={true}
            rows={2}
            style={{ marginTop: theme.spacing(2) }}
          />
          <Field
            component={TextField}
            name="emails"
            label={t_i18n('Emails (1 / line)')}
            onSubmit={onUpdate}
            fullWidth={true}
            multiline={true}
            rows={20}
            style={{ marginTop: theme.spacing(2) }}
            required
            onBeforePaste={(pastedText: string) => {
              // on pasting data, we try to extract emails
              const extractedEmails = parseEmailList(pastedText);
              if (extractedEmails.length > 0) {
                MESSAGING$.notifySuccess(t_i18n('', { id: '{count} email address(es) extracted from pasted text', values: { count: extractedEmails.length } }));
                return extractedEmails.join('\n'); // alter the pasted content
              }
              return pastedText; // do not alter pasted content; it's probably invalid anyway
            }}
          />
          {!isEdition && (
            <div style={{ marginTop: theme.spacing(2), textAlign: 'right' }}>
              <Button
                variant="secondary"
                onClick={handleReset}
                disabled={isSubmitting}
                style={{ marginLeft: theme.spacing(2) }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
                style={{ marginLeft: theme.spacing(2) }}
              >
                {t_i18n('Create')}
              </Button>
            </div>
          )}
        </>
      )}
    </Formik>
  );
};

export default DisseminationListForm;
