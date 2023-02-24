import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../../common/form/OpenVocabField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useYupSchemaBuilder } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';

const toolMutationFieldPatch = graphql`
  mutation ToolEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    toolEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...ToolEditionOverview_tool
        ...Tool_tool
      }
    }
  }
`;

export const toolEditionOverviewFocus = graphql`
  mutation ToolEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    toolEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const toolMutationRelationAdd = graphql`
  mutation ToolEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    toolEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...ToolEditionOverview_tool
        }
      }
    }
  }
`;

const toolMutationRelationDelete = graphql`
  mutation ToolEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    toolEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...ToolEditionOverview_tool
      }
    }
  }
`;

const ToolEditionOverviewComponent = (props) => {
  const { tool, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const basicShape = {
    name: Yup.string().required(t('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number(),
    tool_types: Yup.array(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const toolValidator = useYupSchemaBuilder('Tool', basicShape);

  const queries = {
    fieldPatch: toolMutationFieldPatch,
    relationAdd: toolMutationRelationAdd,
    relationDelete: toolMutationRelationDelete,
    editionFocus: toolEditionOverviewFocus,
  };
  const editor = useFormEditor(tool, enableReferences, queries, toolValidator);

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
      R.assoc('tool_types', values.tool_types),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: tool.id,
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
      toolValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: tool.id,
              input: { key: name, value: finalValue },
            },
          });
        })
        .catch(() => false);
    }
  };

  const killChainPhases = R.pipe(
    R.pathOr([], ['killChainPhases', 'edges']),
    R.map((n) => ({
      label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
      value: n.node.id,
    })),
  )(tool);
  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(tool)),
    R.assoc('killChainPhases', killChainPhases),
    R.assoc('objectMarking', convertMarkings(tool)),
    R.assoc('x_opencti_workflow_id', convertStatus(t, tool)),
    R.assoc('tool_types', tool.tool_types ?? []),
    R.pick([
      'name',
      'description',
      'createdBy',
      'killChainPhases',
      'objectMarking',
      'x_opencti_workflow_id',
      'tool_types',
      'confidence',
    ]),
  )(tool);
  return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={toolValidator}
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
            <ConfidenceField
              name="confidence"
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
              label={t('Confidence')}
              fullWidth={true}
              containerStyle={fieldSpacingContainerStyle}
              editContext={context}
              variant="edit"
            />
            <KillChainPhasesField
              name="killChainPhases"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="killChainPhases" />
              }
              onChange={editor.changeKillChainPhases}
            />
            {tool.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Tool"
                onFocus={editor.changeFocus}
                onChange={handleSubmitField}
                setFieldValue={setFieldValue}
                style={{ marginTop: 20 }}
                helpertext={
                  <SubscriptionFocus context={context} fieldName="x_opencti_workflow_id" />
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
            <OpenVocabField
              type="tool_types_ov"
              name="tool_types"
              label={t('Tool types')}
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              variant="edit"
              multiple={true}
              editContext={context}
            />
            {enableReferences && isValid && dirty && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                setFieldValue={setFieldValue}
                open={false}
                values={values.references}
                id={tool.id}
              />
            )}
          </Form>
        )}
      </Formik>
  );
};

export default createFragmentContainer(ToolEditionOverviewComponent, {
  tool: graphql`
      fragment ToolEditionOverview_tool on Tool {
        id
        name
        description
        tool_types
        confidence
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        killChainPhases {
          edges {
            node {
              id
              kill_chain_name
              phase_name
              x_opencti_order
            }
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
