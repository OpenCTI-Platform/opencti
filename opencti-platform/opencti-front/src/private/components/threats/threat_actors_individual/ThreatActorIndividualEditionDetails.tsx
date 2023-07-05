import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import * as Yup from 'yup';
import * as R from 'ramda';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { isNone, useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import OpenVocabField from '../../common/form/OpenVocabField';
import { parse } from '../../../../utils/Time';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { Option } from '../../common/form/ReferenceField';
import {
  ThreatActorIndividualEditionDetails_ThreatActorIndividual$key,
} from './__generated__/ThreatActorIndividualEditionDetails_ThreatActorIndividual.graphql';
import {
  ThreatActorIndividualEditionDetailsFocusMutation,
} from './__generated__/ThreatActorIndividualEditionDetailsFocusMutation.graphql';
import {
  ThreatActorIndividualEditionDetailsFieldPatchMutation,
} from './__generated__/ThreatActorIndividualEditionDetailsFieldPatchMutation.graphql';

const threatActorIndividualMutationFieldPatch = graphql`
  mutation ThreatActorIndividualEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    threatActorIndividualFieldPatch(id: $id, input: $input, commitMessage: $commitMessage, references: $references) {
      ...ThreatActorIndividualEditionDetails_ThreatActorIndividual
      ...ThreatActorIndividual_ThreatActorIndividual
    }
  }
`;

const ThreatActorIndividualEditionDetailsFocus = graphql`
  mutation ThreatActorIndividualEditionDetailsFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    threatActorIndividualContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const threatActorIndividualEditionDetailsFragment = graphql`
  fragment ThreatActorIndividualEditionDetails_ThreatActorIndividual on ThreatActorIndividual {
    id
    first_seen
    last_seen
    sophistication
    resource_level
    primary_motivation
    secondary_motivations
    personal_motivations
    goals
    roles
  }
`;

interface ThreatActorIndividualEditionDetailsProps {
  threatActorIndividualRef: ThreatActorIndividualEditionDetails_ThreatActorIndividual$key;
  context:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface ThreatActorIndividualEditionDetailsFormValues {
  message?: string;
  references?: Option[];
  first_seen?: Option;
  last_seen?: Option;
  goals: string;
}

const ThreatActorIndividualEditionDetailsComponent: FunctionComponent<ThreatActorIndividualEditionDetailsProps> = ({
  threatActorIndividualRef,
  context,
  enableReferences,
  handleClose,
}) => {
  const { t } = useFormatter();
  const threatActorIndividual = useFragment(threatActorIndividualEditionDetailsFragment, threatActorIndividualRef);
  const [commitFieldPatch] = useMutation<ThreatActorIndividualEditionDetailsFieldPatchMutation>(
    threatActorIndividualMutationFieldPatch,
  );
  const [commitEditionDetailsFocus] = useMutation<ThreatActorIndividualEditionDetailsFocusMutation>(
    ThreatActorIndividualEditionDetailsFocus,
  );

  const ThreatActorIndividualValidation = () => Yup.object().shape({
    first_seen: Yup.date()
      .nullable()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    last_seen: Yup.date()
      .nullable()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    sophistication: Yup.object().nullable(),
    resource_level: Yup.object().nullable(),
    roles: Yup.array().nullable(),
    primary_motivation: Yup.object().nullable(),
    secondary_motivations: Yup.array().nullable(),
    personal_motivations: Yup.array().nullable(),
    goals: Yup.string().nullable(),
    references: Yup.array(),
  });
  const handleChangeFocus = (name: string) => {
    commitEditionDetailsFocus({
      variables: {
        id: threatActorIndividual.id,
        input: {
          focusOn: name,
        },
      },
    });
  };
  const onSubmit: FormikConfig<ThreatActorIndividualEditionDetailsFormValues>['onSubmit'] = (
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
      goals: values.goals.length ? R.split('\n', values.goals) : [],
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));

    commitFieldPatch({
      variables: {
        id: threatActorIndividual.id,
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
  const handleSubmitField = (name: string, value: string | string [] | null) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'goals') {
        finalValue = value && value.length > 0 ? R.split('\n', value as string) : [];
      }
      ThreatActorIndividualValidation()
        .validateAt(name, { [name]: value })
        .then(() => {
          commitFieldPatch({
            variables: {
              id: threatActorIndividual.id,
              input: [{ key: name, value: [finalValue as string ?? ''] }],
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = {
    first_seen: !isNone(threatActorIndividual.first_seen) ? threatActorIndividual.first_seen : null,
    last_seen: !isNone(threatActorIndividual.last_seen) ? threatActorIndividual.last_seen : null,
    secondary_motivations: threatActorIndividual.secondary_motivations,
    personal_motivations: threatActorIndividual.personal_motivations,
    primary_motivations: threatActorIndividual.primary_motivation,
    roles: threatActorIndividual.roles,
    sophistication: threatActorIndividual.sophistication,
    resource_level: threatActorIndividual.resource_level,
    goals: R.join('\n', threatActorIndividual.goals ? threatActorIndividual.goals : []),
  };
  return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={ThreatActorIndividualValidation}
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
            <div>
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={DateTimePickerField}
                  name="first_seen"
                  onFocus={handleChangeFocus}
                  onSubmit={handleSubmitField}
                  TextFieldProps={{
                    label: t('First seen'),
                    variant: 'standard',
                    fullWidth: true,
                    helperText: (
                      <SubscriptionFocus
                        context={context}
                        fieldName="first_seen"
                      />
                    ),
                  }}
                />
                <Field
                  component={DateTimePickerField}
                  name="last_seen"
                  onFocus={handleChangeFocus}
                  onSubmit={handleSubmitField}
                  TextFieldProps={{
                    label: t('Last seen'),
                    variant: 'standard',
                    fullWidth: true,
                    style: { marginTop: 20 },
                    helperText: (
                      <SubscriptionFocus
                        context={context}
                        fieldName="last_seen"
                      />
                    ),
                  }}
                />
                <OpenVocabField
                  label={t('Sophistication')}
                  type="threat_actor_individual_sophistication_ov"
                  name="sophistication"
                  onFocus={handleChangeFocus}
                  onChange={(name, value) => setFieldValue(name, value)}
                  onSubmit={handleSubmitField}
                  containerStyle={fieldSpacingContainerStyle}
                  variant="edit"
                  multiple={false}
                  editContext={context}
                />
                <OpenVocabField
                  label={t('Resource level')}
                  type="attack-resource-level-ov"
                  name="resource_level"
                  onFocus={handleChangeFocus}
                  onChange={(name, value) => setFieldValue(name, value)}
                  onSubmit={handleSubmitField}
                  containerStyle={fieldSpacingContainerStyle}
                  variant="edit"
                  multiple={false}
                  editContext={context}
                />
                <OpenVocabField
                  label={t('Roles')}
                  type="threat-actor-individual-role-ov"
                  name="roles"
                  onFocus={handleChangeFocus}
                  onChange={(name, value) => setFieldValue(name, value)}
                  onSubmit={handleSubmitField}
                  containerStyle={fieldSpacingContainerStyle}
                  variant="edit"
                  multiple={true}
                  editContext={context}
                />
                <OpenVocabField
                  label={t('Primary motivation')}
                  type="attack-motivation-ov"
                  name="primary_motivation"
                  onFocus={handleChangeFocus}
                  onChange={(name, value) => setFieldValue(name, value)}
                  onSubmit={handleSubmitField}
                  containerStyle={fieldSpacingContainerStyle}
                  variant="edit"
                  multiple={false}
                  editContext={context}
                />
                <OpenVocabField
                  label={t('Secondary motivations')}
                  type="attack-motivation-ov"
                  name="secondary_motivations"
                  onFocus={handleChangeFocus}
                  onChange={(name, value) => setFieldValue(name, value)}
                  onSubmit={handleSubmitField}
                  containerStyle={fieldSpacingContainerStyle}
                  variant="edit"
                  multiple={true}
                  editContext={context}
                />
                <OpenVocabField
                  label={t('Personal motivations')}
                  type="attack-motivation-ov"
                  name="personal_motivations"
                  onFocus={handleChangeFocus}
                  onChange={(name, value) => setFieldValue(name, value)}
                  onSubmit={handleSubmitField}
                  containerStyle={fieldSpacingContainerStyle}
                  variant="edit"
                  multiple={true}
                  editContext={context}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="goals"
                  label={t('Goals (1 / line)')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 20 }}
                  onFocus={handleChangeFocus}
                  onSubmit={handleSubmitField}
                  helperText={
                    <SubscriptionFocus context={context} fieldName="goals" />
                  }
                />
                {enableReferences && (
                  <CommitMessage
                    submitForm={submitForm}
                    disabled={isSubmitting || !isValid || !dirty}
                    setFieldValue={setFieldValue}
                    open={false}
                    values={values.references}
                    id={threatActorIndividual.id}
                  />
                )}
              </Form>
            </div>
          )}
        </Formik>
      </div>
  );
};

export default ThreatActorIndividualEditionDetailsComponent;
