import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import {
  IncidentEditionDetailsFieldPatchMutation,
} from './__generated__/IncidentEditionDetailsFieldPatchMutation.graphql';
import { IncidentEditionDetailsFocusMutation } from './__generated__/IncidentEditionDetailsFocusMutation.graphql';
import { Option } from '../../common/form/ReferenceField';
import { IncidentEditionDetails_incident$key } from './__generated__/IncidentEditionDetails_incident.graphql';

const incidentMutationFieldPatch = graphql`
  mutation IncidentEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    incidentEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...IncidentEditionDetails_incident
        ...Incident_incident
      }
    }
  }
`;

const incidentEditionDetailsFocus = graphql`
  mutation IncidentEditionDetailsFocusMutation($id: ID!, $input: EditContext!) {
    incidentEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const incidentEditionDetailsFragment = graphql`
    fragment IncidentEditionDetails_incident on Incident {
        id
        first_seen
        last_seen
        source
        objective
        is_inferred
    }
  `;

const incidentEditionDetailsValidation = (t: (v: string) => string) => Yup.object().shape({
  first_seen: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  last_seen: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  objective: Yup.string().nullable(),
  source: Yup.string().nullable(),
});

interface IncidentEditionDetailsProps {
  incidentRef: IncidentEditionDetails_incident$key ;
  context: readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[] | null
  enableReferences?: boolean
  handleClose: () => void
}

interface IncidentEditionDetailsFormValues {
  message?: string
  references?: Option[]
  first_seen?: Option
  last_seen?: Option
}
const IncidentEditionDetails : FunctionComponent<IncidentEditionDetailsProps> = ({ incidentRef, context, enableReferences = false, handleClose }) => {
  const { t } = useFormatter();

  const incident = useFragment(incidentEditionDetailsFragment, incidentRef);
  const isInferred = incident.is_inferred;

  const [commitFieldPatch] = useMutation<IncidentEditionDetailsFieldPatchMutation>(incidentMutationFieldPatch);
  const [commitEditionDetailsFocus] = useMutation<IncidentEditionDetailsFocusMutation>(incidentEditionDetailsFocus);

  const handleChangeFocus = (name: string) => {
    commitEditionDetailsFocus({
      variables: {
        id: incident.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const onSubmit : FormikConfig<IncidentEditionDetailsFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);

    const inputValues = Object.entries({
      ...otherValues,
      first_seen: values.first_seen?.value,
      last_seen: values.last_seen?.value,
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));

    commitFieldPatch({
      variables: {
        id: incident.id,
        input: inputValues,
        commitMessage: commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name: string, value: string | string[] | null) => {
    if (!enableReferences) {
      const finalValue: string = value as string;
      incidentEditionDetailsValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitFieldPatch({
            variables: {
              id: incident.id,
              input: [{ key: name, value: [finalValue ?? ''] }],
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = {
    first_seen: incident.first_seen,
    last_seen: incident.last_seen,
    source: incident.source,
    objective: incident.objective,
  };

  return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={incidentEditionDetailsValidation(t)}
        onSubmit={onSubmit}
      >
        {({
          submitForm,
          isSubmitting,
          setFieldValue,
          values,
        }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={DateTimePickerField}
              name="first_seen"
              disabled={isInferred}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              TextFieldProps={{
                label: t('First seen'),
                variant: 'standard',
                fullWidth: true,
                helperText: (
                  <SubscriptionFocus context={context} fieldName="first_seen" />
                ),
              }}
            />
            <Field
              component={DateTimePickerField}
              name="last_seen"
              label={t('Last seen')}
              disabled={isInferred}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              TextFieldProps={{
                label: t('Last seen'),
                variant: 'standard',
                fullWidth: true,
                style: { marginTop: 20 },
                helperText: (
                  <SubscriptionFocus context={context} fieldName="last_seen" />
                ),
              }}
            />
            <Field
              component={TextField}
              variant="standard"
              name="source"
              label={t('Source')}
              fullWidth={true}
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="source" />
              }
            />
            <Field
              component={TextField}
              variant="standard"
              name="objective"
              label={t('Objective')}
              fullWidth={true}
              multiline={true}
              rows={4}
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="objective" />
              }
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                setFieldValue={setFieldValue}
                values={values.references}
                id={incident.id}
                open={false}
              />
            )}
          </Form>
        )}
      </Formik>
  );
};

export default IncidentEditionDetails;
