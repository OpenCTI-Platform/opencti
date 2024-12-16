import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { useTheme } from '@mui/styles';
import { isNone, useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { IncidentEditionDetailsFieldPatchMutation } from './__generated__/IncidentEditionDetailsFieldPatchMutation.graphql';
import { IncidentEditionDetailsFocusMutation } from './__generated__/IncidentEditionDetailsFocusMutation.graphql';
import { Option } from '../../common/form/ReferenceField';
import { IncidentEditionDetails_incident$key } from './__generated__/IncidentEditionDetails_incident.graphql';
import { parse } from '../../../../utils/Time';
import { GenericContext } from '../../common/model/GenericContextModel';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';

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
    confidence
    entity_type
  }
`;

const incidentEditionDetailsValidation = (t: (v: string) => string) => Yup.object().shape({
  first_seen: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  last_seen: Yup.date()
    .nullable()
    .min(
      Yup.ref('first_seen'),
      "The last seen date can't be before first seen date",
    )
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  objective: Yup.string().nullable(),
  source: Yup.string().nullable(),
});

interface IncidentEditionDetailsProps {
  incidentRef: IncidentEditionDetails_incident$key;
  context?: readonly (GenericContext | null)[] | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface IncidentEditionDetailsFormValues {
  message?: string;
  references?: Option[];
  first_seen?: Option;
  last_seen?: Option;
}
const IncidentEditionDetails: FunctionComponent<
IncidentEditionDetailsProps
> = ({ incidentRef, context, enableReferences = false, handleClose }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const incident = useFragment(incidentEditionDetailsFragment, incidentRef);
  const isInferred = incident.is_inferred;

  const [commitFieldPatch] = useApiMutation<IncidentEditionDetailsFieldPatchMutation>(
    incidentMutationFieldPatch,
  );
  const [commitEditionDetailsFocus] = useApiMutation<IncidentEditionDetailsFocusMutation>(
    incidentEditionDetailsFocus,
  );

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

  const onSubmit: FormikConfig<IncidentEditionDetailsFormValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);

    const inputValues = Object.entries({
      ...otherValues,
      first_seen: values.first_seen ? parse(values.first_seen).format() : null,
      last_seen: values.last_seen ? parse(values.last_seen).format() : null,
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));

    commitFieldPatch({
      variables: {
        id: incident.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
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
      commitFieldPatch({
        variables: {
          id: incident.id,
          input: [{ key: name, value: [finalValue ?? ''] }],
        },
      });
    }
  };

  const initialValues = {
    first_seen: !isNone(incident.first_seen) ? incident.first_seen : null,
    last_seen: !isNone(incident.last_seen) ? incident.last_seen : null,
    source: incident.source,
    objective: incident.objective,
    references: [],
  };

  return (
    <Formik<IncidentEditionDetailsFormValues>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={incidentEditionDetailsValidation(t_i18n)}
      onSubmit={onSubmit}
    >
      {({
        submitForm,
        isSubmitting,
        setFieldValue,
        values,
        isValid,
        dirty,
      }) => (
        <Form style={{ marginTop: theme.spacing(2) }}>
          <AlertConfidenceForEntity entity={incident} />
          <Field
            component={DateTimePickerField}
            name="first_seen"
            disabled={isInferred}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            textFieldProps={{
              label: t_i18n('First seen'),
              variant: 'standard',
              fullWidth: true,
              helperText: (
                <SubscriptionFocus context={context} fieldName="first_seen"/>
              ),
            }}
          />
          <Field
            component={DateTimePickerField}
            name="last_seen"
            label={t_i18n('Last seen')}
            disabled={isInferred}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            textFieldProps={{
              label: t_i18n('Last seen'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
              helperText: (
                <SubscriptionFocus context={context} fieldName="last_seen"/>
              ),
            }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="source"
            label={t_i18n('Source')}
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
            label={t_i18n('Objective')}
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
              disabled={isSubmitting || !isValid || !dirty}
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
