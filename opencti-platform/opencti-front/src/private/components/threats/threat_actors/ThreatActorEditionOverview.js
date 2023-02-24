import React from 'react';
import * as R from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useFormatter } from '../../../../components/i18n';
import { useYupSchemaBuilder } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';

const threatActorMutationFieldPatch = graphql`
  mutation ThreatActorEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    threatActorEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...ThreatActorEditionOverview_threatActor
        ...ThreatActor_threatActor
      }
    }
  }
`;

export const threatActorEditionOverviewFocus = graphql`
  mutation ThreatActorEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    threatActorEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const threatActorMutationRelationAdd = graphql`
  mutation ThreatActorEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    threatActorEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...ThreatActorEditionOverview_threatActor
        }
      }
    }
  }
`;

const threatActorMutationRelationDelete = graphql`
  mutation ThreatActorEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    threatActorEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...ThreatActorEditionOverview_threatActor
      }
    }
  }
`;

const ThreatActorEditionOverviewComponent = (props) => {
  const { threatActor, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const basicShape = {
    name: Yup.string().required(t('This field is required')),
    threat_actor_types: Yup.array(),
    confidence: Yup.number(),
    description: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const threatActorValidator = useYupSchemaBuilder('Threat-Actor', basicShape);

  const queries = {
    fieldPatch: threatActorMutationFieldPatch,
    relationAdd: threatActorMutationRelationAdd,
    relationDelete: threatActorMutationRelationDelete,
    editionFocus: threatActorEditionOverviewFocus,
  };
  const editor = useFormEditor(threatActor, enableReferences, queries, threatActorValidator);

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: threatActor.id,
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
      threatActorValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: threatActor.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const createdBy = convertCreatedBy(threatActor);
  const objectMarking = convertMarkings(threatActor);
  const status = convertStatus(t, threatActor);
  const killChainPhases = R.pipe(
    R.pathOr([], ['killChainPhases', 'edges']),
    R.map((n) => ({
      label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
      value: n.node.id,
    })),
  )(threatActor);
  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('killChainPhases', killChainPhases),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.assoc(
      'threat_actor_types',
      threatActor.threat_actor_types ? threatActor.threat_actor_types : [],
    ),
    R.pick([
      'name',
      'threat_actor_types',
      'confidence',
      'description',
      'createdBy',
      'killChainPhases',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(threatActor);
  return (
      <Formik
        enableReinitialize={true}
        initialValues={{ ...initialValues, references: [] }}
        validationSchema={threatActorValidator}
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
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <OpenVocabField
              variant="edit"
              type="threat-actor-type-ov"
              name="threat_actor_types"
              label={t('Threat actor types')}
              containerStyle={{ width: '100%', marginTop: 20 }}
              multiple={true}
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              onChange={(name, value) => setFieldValue(name, value)}
              editContext={context}
            />
            <ConfidenceField
              name="confidence"
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
              label={t('Confidence')}
              fullWidth={true}
              containerStyle={{ width: '100%', marginTop: 20 }}
              editContext={context}
              variant="edit"
            />
            <Field
              component={MarkDownField}
              name="description"
              label={t('Description')}
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
            {threatActor.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Threat-Actor"
                onFocus={editor.changeFocus}
                onChange={handleSubmitField}
                setFieldValue={setFieldValue}
                style={{ marginTop: 20 }}
                helpertext={
                  <SubscriptionFocus context={context} field="x_opencti_workflow_id" />
                }
              />
            )}
            <CreatedByField
              name="createdBy"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdBy" />
              }
              onChange={editor.changeCreated}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus context={context} fieldname="objectMarking" />
              }
              onChange={editor.changeMarking}
            />
            {enableReferences && isValid && dirty && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                setFieldValue={setFieldValue}
                open={false}
                values={values.references}
                id={threatActor.id}
              />
            )}
          </Form>
        )}
      </Formik>
  );
};

export default createFragmentContainer(ThreatActorEditionOverviewComponent, {
  threatActor: graphql`
      fragment ThreatActorEditionOverview_threatActor on ThreatActor {
        id
        name
        threat_actor_types
        confidence
        description
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
          }
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
});
