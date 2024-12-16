import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { useTheme } from '@mui/styles';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertAssignees, convertCreatedBy, convertKillChainPhases, convertMarkings, convertStatus } from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useFormatter } from '../../../../components/i18n';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { Option } from '../../common/form/ReferenceField';
import { ThreatActorIndividualEditionOverview_ThreatActorIndividual$key } from './__generated__/ThreatActorIndividualEditionOverview_ThreatActorIndividual.graphql';
import { GenericContext } from '../../common/model/GenericContextModel';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import type { Theme } from '../../../../components/Theme';

const ThreatActorIndividualMutationFieldPatch = graphql`
  mutation ThreatActorIndividualEditionOverviewFieldPatchMutation(
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
      ...ThreatActorIndividualEditionOverview_ThreatActorIndividual
      ...ThreatActorIndividual_ThreatActorIndividual
    }
  }
`;

export const ThreatActorIndividualEditionOverviewFocus = graphql`
  mutation ThreatActorIndividualEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    threatActorIndividualContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

export const threatActorIndividualRelationAddMutation = graphql`
  mutation ThreatActorIndividualEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    threatActorIndividualRelationAdd(id: $id, input: $input) {
      from {
        ...ThreatActorIndividualEditionOverview_ThreatActorIndividual
      }
    }
  }
`;

export const ThreatActorIndividualMutationRelationDelete = graphql`
  mutation ThreatActorIndividualEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    threatActorIndividualRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      ...ThreatActorIndividualEditionOverview_ThreatActorIndividual
    }
  }
`;

const threatActorIndividualEditionOverviewFragment = graphql`
  fragment ThreatActorIndividualEditionOverview_ThreatActorIndividual on ThreatActorIndividual {
    id
    name
    threat_actor_types
    confidence
    entity_type
    description
    x_opencti_stix_ids
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
  }
`;

interface ThreatActorIndividualEditionOverviewProps {
  threatActorIndividualRef: ThreatActorIndividualEditionOverview_ThreatActorIndividual$key;
  context?: readonly (GenericContext | null)[] | null;
  enableReferences: boolean;
  handleClose: () => void;
}

interface ThreatActorIndividualEditionFormValues {
  message?: string;
  references?: Option[];
  createdBy: Option | undefined;
  x_opencti_workflow_id: Option;
  objectMarking?: Option[];
  objectAssignee?: Option[];
  killChainPhases?: Option[];
}

const ThreatActorIndividualEditionOverviewComponent: FunctionComponent<
ThreatActorIndividualEditionOverviewProps
> = ({ threatActorIndividualRef, enableReferences, handleClose, context }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const threatActorIndividual = useFragment(
    threatActorIndividualEditionOverviewFragment,
    threatActorIndividualRef,
  );
  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    threat_actor_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    description: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const ThreatActorIndividualValidator = useSchemaEditionValidation(
    'Threat-Actor-Individual',
    basicShape,
  );
  const queries = {
    fieldPatch: ThreatActorIndividualMutationFieldPatch,
    relationAdd: threatActorIndividualRelationAddMutation,
    relationDelete: ThreatActorIndividualMutationRelationDelete,
    editionFocus: ThreatActorIndividualEditionOverviewFocus,
  };
  const editor = useFormEditor(
    threatActorIndividual as GenericData,
    enableReferences,
    queries,
    ThreatActorIndividualValidator,
  );
  const onSubmit: FormikConfig<ThreatActorIndividualEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);
    const inputValues = Object.entries({
      ...otherValues,
      createdBy: values.createdBy?.value,
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
      objectAssignee: (values.objectAssignee ?? []).map(({ value }) => value),
      killChainPhases: (values.killChainPhases ?? []).map(
        ({ value }) => value,
      ),
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
  const handleSubmitField = (
    name: string,
    value: string | string[] | number | number[] | null,
  ) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as unknown as Option).value;
      }
      ThreatActorIndividualValidator.validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: threatActorIndividual.id,
              input: [
                {
                  key: name,
                  value: Array.isArray(finalValue) ? finalValue : [finalValue],
                },
              ],
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = {
    name: threatActorIndividual.name,
    description: threatActorIndividual.description,
    createdBy: convertCreatedBy(threatActorIndividual) as Option,
    objectMarking: convertMarkings(threatActorIndividual),
    objectAssignee: convertAssignees(threatActorIndividual),
    killChainPhases: convertKillChainPhases(threatActorIndividual),
    x_opencti_workflow_id: convertStatus(t_i18n, threatActorIndividual) as Option,
    confidence: threatActorIndividual.confidence,
    threat_actor_types: threatActorIndividual.threat_actor_types ?? [],
    references: [],
  };
  return (
    <Formik<ThreatActorIndividualEditionFormValues>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={ThreatActorIndividualValidator}
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
          <AlertConfidenceForEntity entity={threatActorIndividual} />
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <OpenVocabField
            variant="edit"
            type="threat-actor-individual-type-ov"
            name="threat_actor_types"
            label={t_i18n('Threat actor types')}
            containerStyle={{ width: '100%', marginTop: 20 }}
            multiple={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            editContext={context}
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Threat-Actor-Group"
            containerStyle={{ width: '100%', marginTop: 20 }}
            editContext={context}
            variant="edit"
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          {threatActorIndividual.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Threat-Actor-Individual"
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
              setFieldValue={setFieldValue}
              style={{ marginTop: 20 }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  field="x_opencti_workflow_id"
                />
              }
            />
          )}
          <CreatedByField
            name="createdBy"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus context={context} fieldName="createdBy" />
            }
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking" />
            }
            setFieldValue={setFieldValue}
            onChange={editor.changeMarking}
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
      )}
    </Formik>
  );
};

export default ThreatActorIndividualEditionOverviewComponent;
