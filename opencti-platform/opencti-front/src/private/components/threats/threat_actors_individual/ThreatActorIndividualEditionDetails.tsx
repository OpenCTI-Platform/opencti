import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import * as Yup from 'yup';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import {
  ThreatActorIndividualMutationRelationDelete,
  threatActorIndividualRelationAddMutation,
} from '@components/threats/threat_actors_individual/ThreatActorIndividualEditionOverview';
import { GenericContext } from '../../common/model/GenericContextModel';
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
import { ThreatActorIndividualEditionDetails_ThreatActorIndividual$key } from './__generated__/ThreatActorIndividualEditionDetails_ThreatActorIndividual.graphql';
import { ThreatActorIndividualEditionDetailsFocusMutation } from './__generated__/ThreatActorIndividualEditionDetailsFocusMutation.graphql';
import { useSchemaEditionValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const threatActorIndividualMutationFieldPatch = graphql`
  mutation ThreatActorIndividualEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    threatActorIndividualFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
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
    confidence
    entity_type
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
  }
`;

interface ThreatActorIndividualEditionDetailsProps {
  threatActorIndividualRef: ThreatActorIndividualEditionDetails_ThreatActorIndividual$key;
  context?: readonly (GenericContext | null)[] | null;
  enableReferences: boolean;
  handleClose: () => void;
}

interface ThreatActorIndividualEditionDetailsFormValues {
  message?: string;
  references?: Option[];
  first_seen?: Option;
  last_seen?: Option;
  goals: string;
}

const THREAT_ACTOR_INDIVIDUAL_TYPE = 'Threat-Actor-Individual';

const ThreatActorIndividualEditionDetailsComponent: FunctionComponent<
ThreatActorIndividualEditionDetailsProps
> = ({ threatActorIndividualRef, context, enableReferences, handleClose }) => {
  const { t_i18n } = useFormatter();
  const threatActorIndividual = useFragment(
    threatActorIndividualEditionDetailsFragment,
    threatActorIndividualRef,
  );
  const [commitEditionDetailsFocus] = useApiMutation<ThreatActorIndividualEditionDetailsFocusMutation>(
    ThreatActorIndividualEditionDetailsFocus,
  );
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    THREAT_ACTOR_INDIVIDUAL_TYPE,
  );
  const basicShape = {
    first_seen: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    last_seen: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    sophistication: Yup.string().nullable(),
    resource_level: Yup.string().nullable(),
    roles: Yup.array().nullable(),
    primary_motivation: Yup.string().nullable(),
    secondary_motivations: Yup.array().nullable(),
    personal_motivations: Yup.array().nullable(),
    goals: Yup.string().nullable(),
    references: Yup.array(),
  };
  const individualThreatActorValidator = useSchemaEditionValidation(
    THREAT_ACTOR_INDIVIDUAL_TYPE,
    basicShape,
  );

  const queries = {
    fieldPatch: threatActorIndividualMutationFieldPatch,
    relationAdd: threatActorIndividualRelationAddMutation,
    relationDelete: ThreatActorIndividualMutationRelationDelete,
    editionFocus: ThreatActorIndividualEditionDetailsFocus,
  };

  const editor = useFormEditor(
    threatActorIndividual as GenericData,
    enableReferences,
    queries,
    individualThreatActorValidator,
  );

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
  const onSubmit: FormikConfig<ThreatActorIndividualEditionDetailsFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);

    const inputValues = Object.entries({
      ...otherValues,
      first_seen: values.first_seen
        ? parse(values.first_seen).format()
        : null,
      last_seen: values.last_seen ? parse(values.last_seen).format() : null,
      goals:
          values.goals && values.goals.length ? values.goals.split('\n') : [],
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));

    editor.fieldPatch({
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
  const handleSubmitField = (name: string, value: string | string[] | null) => {
    if (!enableReferences) {
      individualThreatActorValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: threatActorIndividual.id,
              input: [
                { key: name, value: Array.isArray(value) ? value : [value] },
              ],
            },
          });
        })
        .catch(() => false);
    }
  };

  const handleSubmitGoals = (name: string, value: string) => {
    if (!enableReferences) {
      const finalValue = value && value.length > 0 ? value.split('\n') : [];
      individualThreatActorValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: threatActorIndividual.id,
              input: [{ key: name, value: finalValue }],
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = {
    first_seen: !isNone(threatActorIndividual.first_seen)
      ? threatActorIndividual.first_seen
      : null,
    last_seen: !isNone(threatActorIndividual.last_seen)
      ? threatActorIndividual.last_seen
      : null,
    secondary_motivations: threatActorIndividual.secondary_motivations ?? [],
    personal_motivations: threatActorIndividual.personal_motivations ?? [],
    primary_motivation: threatActorIndividual.primary_motivation ?? '',
    roles: threatActorIndividual.roles ?? [],
    sophistication: threatActorIndividual.sophistication ?? '',
    resource_level: threatActorIndividual.resource_level ?? '',
    goals: (threatActorIndividual.goals ?? []).join('\n'),
  };
  return (
    <div>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues as never}
        validationSchema={individualThreatActorValidator}
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
              <AlertConfidenceForEntity entity={threatActorIndividual} />
              <Field
                component={DateTimePickerField}
                name="first_seen"
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                textFieldProps={{
                  label: t_i18n('First seen'),
                  required: (mandatoryAttributes.includes('first_seen')),
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
                textFieldProps={{
                  label: t_i18n('Last seen'),
                  required: (mandatoryAttributes.includes('last_seen')),
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
                label={t_i18n('Sophistication')}
                type="threat_actor_individual_sophistication_ov"
                name="sophistication"
                required={(mandatoryAttributes.includes('sophistication'))}
                onFocus={handleChangeFocus}
                onChange={(name, value) => setFieldValue(name, value)}
                onSubmit={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                variant="edit"
                multiple={false}
                editContext={context}
              />
              <OpenVocabField
                label={t_i18n('Resource level')}
                type="attack-resource-level-ov"
                name="resource_level"
                required={(mandatoryAttributes.includes('resource_level'))}
                onFocus={handleChangeFocus}
                onChange={(name, value) => setFieldValue(name, value)}
                onSubmit={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                variant="edit"
                multiple={false}
                editContext={context}
              />
              <OpenVocabField
                label={t_i18n('Roles')}
                type="threat-actor-individual-role-ov"
                name="roles"
                required={(mandatoryAttributes.includes('roles'))}
                onFocus={handleChangeFocus}
                onChange={(name, value) => setFieldValue(name, value)}
                onSubmit={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                variant="edit"
                multiple={true}
                editContext={context}
              />
              <OpenVocabField
                label={t_i18n('Primary motivation')}
                type="attack-motivation-ov"
                name="primary_motivation"
                required={(mandatoryAttributes.includes('primary_motivation'))}
                onFocus={handleChangeFocus}
                onChange={(name, value) => setFieldValue(name, value)}
                onSubmit={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                variant="edit"
                multiple={false}
                editContext={context}
              />
              <OpenVocabField
                label={t_i18n('Secondary motivations')}
                type="attack-motivation-ov"
                name="secondary_motivations"
                required={(mandatoryAttributes.includes('secondary_motivations'))}
                onFocus={handleChangeFocus}
                onChange={(name, value) => setFieldValue(name, value)}
                onSubmit={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                variant="edit"
                multiple={true}
                editContext={context}
              />
              <OpenVocabField
                label={t_i18n('Personal motivations')}
                type="attack-motivation-ov"
                name="personal_motivations"
                required={(mandatoryAttributes.includes('personal_motivations'))}
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
                name="goals"
                label={t_i18n('Goals (1 / line)')}
                required={(mandatoryAttributes.includes('goals'))}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={{ marginTop: 20 }}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitGoals}
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
