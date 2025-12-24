import React, { FC, useCallback } from 'react';
import { Formik, Form, Field, FormikHelpers } from 'formik';
import { object, string } from 'yup';
import { v4 as uuid } from 'uuid';
import { graphql } from 'react-relay';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import MenuItem from '@mui/material/MenuItem';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import ObjectLabelField from '../form/ObjectLabelField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import { ExternalReferencesField } from '../form/ExternalReferencesField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const identityMutation = graphql`
  mutation IdentityCreationMutation($input: IdentityAddInput!) {
    identityAdd(input: $input) {
      id
      standard_id
      name
      entity_type
    }
  }
`;

interface IdentityFormValues {
  name: string;
  description: string;
  type: string;
  objectMarking: { value: string }[];
  objectLabel: { value: string }[];
  externalReferences: { value: string }[];
}

interface IdentityCreationProps {
  open: boolean;
  inputValue?: string;
  contextual?: boolean;
  onlyAuthors?: boolean;
  dryrun?: boolean;
  handleClose: () => void;
  creationCallback?: (data: unknown) => void;
}

const buildValidationSchema = (t: (key: string) => string) =>
  object({
    name: string().trim().required(t('This field is required')),
    type: string().trim().required(t('This field is required')),
  });

const IdentityCreation: FC<IdentityCreationProps> = ({
  open,
  inputValue = '',
  contextual = false,
  onlyAuthors = false,
  dryrun = false,
  handleClose,
  creationCallback,
}) => {
  const { t_i18n: t } = useFormatter();
  const [commit] = useApiMutation(identityMutation);

  const onSubmit = useCallback(
    (
      values: IdentityFormValues,
      { setSubmitting, resetForm }: FormikHelpers<IdentityFormValues>,
    ) => {
      if (dryrun && contextual && creationCallback) {
        creationCallback({
          identityAdd: {
            ...values,
            id: `identity--${uuid()}`,
          },
        });
        handleClose();
        return;
      }

      const finalValues = {
        ...values,
        objectMarking: values.objectMarking.map((o) => o.value),
        objectLabel: values.objectLabel.map((o) => o.value),
        externalReferences: values.externalReferences.map((o) => o.value),
      };

      commit({
        variables: { input: finalValues },
        onCompleted: (response) => {
          resetForm();
          if (contextual && creationCallback) {
            creationCallback(response);
          }
          setSubmitting(false);
          handleClose();
        },
        onError: () => {
          setSubmitting(false);
        },
      });
    },
    [contextual, creationCallback, dryrun, handleClose],
  );

  return (
    <Formik<IdentityFormValues>
      enableReinitialize
      initialValues={{
        name: inputValue,
        description: '',
        type: '',
        objectMarking: [],
        objectLabel: [],
        externalReferences: [],
      }}
      validationSchema={buildValidationSchema(t)}
      onSubmit={onSubmit}
      onReset={handleClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form>
          <Dialog
            open={open}
            onClose={handleClose}
            fullWidth
            slotProps={{ paper: { elevation: 1 } }}
          >
            <DialogTitle>{t('Create an entity')}</DialogTitle>

            <DialogContent>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth
                detectDuplicate={['Organization', 'Individual']}
              />

              <Field
                component={MarkdownField}
                name="description"
                label={t('Description')}
                fullWidth
                multiline
                rows={4}
                sx={{ mt: 2 }}
              />

              <Field
                component={SelectField}
                variant="standard"
                name="type"
                label={t('Entity type')}
                fullWidth
                containerstyle={fieldSpacingContainerStyle}
              >
                {!onlyAuthors && (
                  <MenuItem value="Sector">{t('Sector')}</MenuItem>
                )}
                <MenuItem value="Organization">{t('Organization')}</MenuItem>
                <MenuItem value="System">{t('System')}</MenuItem>
                <MenuItem value="Individual">{t('Individual')}</MenuItem>
              </Field>

              {!dryrun && (
                <>
                  <ObjectLabelField
                    name="objectLabel"
                    style={fieldSpacingContainerStyle}
                    setFieldValue={setFieldValue}
                    values={values.objectLabel}
                  />

                  <ObjectMarkingField
                    name="objectMarking"
                    style={fieldSpacingContainerStyle}
                    setFieldValue={setFieldValue}
                  />

                  <ExternalReferencesField
                    name="externalReferences"
                    style={fieldSpacingContainerStyle}
                    setFieldValue={setFieldValue}
                    values={values.externalReferences}
                  />
                </>
              )}
            </DialogContent>

            <DialogActions>
              <Button onClick={handleReset} disabled={isSubmitting}>
                {t('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t('Create')}
              </Button>
            </DialogActions>
          </Dialog>
        </Form>
      )}
    </Formik>
  );
};

export default IdentityCreation;
