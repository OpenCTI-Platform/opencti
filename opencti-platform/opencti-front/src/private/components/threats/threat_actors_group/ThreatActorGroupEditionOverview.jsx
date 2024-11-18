import React from 'react';
import * as R from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
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
import { convertCreatedBy, convertKillChainPhases, convertMarkings, convertStatus } from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useFormatter } from '../../../../components/i18n';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const ThreatActorGroupMutationFieldPatch = graphql`
  mutation ThreatActorGroupEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    threatActorGroupEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...ThreatActorGroupEditionOverview_ThreatActorGroup
        ...ThreatActorGroup_ThreatActorGroup
      }
    }
  }
`;

export const ThreatActorGroupEditionOverviewFocus = graphql`
  mutation ThreatActorGroupEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    threatActorGroupEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

export const ThreatActorGroupMutationRelationAdd = graphql`
  mutation ThreatActorGroupEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    threatActorGroupEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...ThreatActorGroupEditionOverview_ThreatActorGroup
        }
      }
    }
  }
`;

export const ThreatActorGroupMutationRelationDelete = graphql`
  mutation ThreatActorGroupEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    threatActorGroupEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...ThreatActorGroupEditionOverview_ThreatActorGroup
      }
    }
  }
`;

const ThreatActorGroupEditionOverviewComponent = (props) => {
  const { threatActorGroup, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();
  const theme = useTheme();

  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    threat_actor_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    description: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const ThreatActorGroupValidator = useSchemaEditionValidation(
    'Threat-Actor-Group',
    basicShape,
  );
  const queries = {
    fieldPatch: ThreatActorGroupMutationFieldPatch,
    relationAdd: ThreatActorGroupMutationRelationAdd,
    relationDelete: ThreatActorGroupMutationRelationDelete,
    editionFocus: ThreatActorGroupEditionOverviewFocus,
  };
  const editor = useFormEditor(
    threatActorGroup,
    enableReferences,
    queries,
    ThreatActorGroupValidator,
  );
  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: threatActorGroup.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };
  const handleSubmitField = (name, value) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      ThreatActorGroupValidator.validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: threatActorGroup.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };
  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(threatActorGroup)),
    R.assoc('killChainPhases', convertKillChainPhases(threatActorGroup)),
    R.assoc('objectMarking', convertMarkings(threatActorGroup)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, threatActorGroup)),
    R.assoc('references', []),
    R.assoc(
      'threat_actor_types',
      threatActorGroup.threat_actor_types
        ? threatActorGroup.threat_actor_types
        : [],
    ),
    R.pick([
      'name',
      'references',
      'threat_actor_types',
      'confidence',
      'description',
      'createdBy',
      'killChainPhases',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(threatActorGroup);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={{ ...initialValues, references: [] }}
      validationSchema={ThreatActorGroupValidator}
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
          <AlertConfidenceForEntity entity={threatActorGroup} />
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            askAi={true}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <OpenVocabField
            variant="edit"
            type="threat-actor-group-type-ov"
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
            askAi={true}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          {threatActorGroup.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Threat-Actor-Group"
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
              id={threatActorGroup.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(
  ThreatActorGroupEditionOverviewComponent,
  {
    threatActorGroup: graphql`
      fragment ThreatActorGroupEditionOverview_ThreatActorGroup on ThreatActorGroup {
        id
        name
        threat_actor_types
        confidence
        entity_type
        description
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
    `,
  },
);
