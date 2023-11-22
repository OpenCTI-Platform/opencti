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
import MarkdownField from '../../../../components/fields/MarkdownField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertKillChainPhases, convertMarkings, convertStatus } from '../../../../utils/edition';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../../common/form/OpenVocabField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useSchemaEditionValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

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
    $input: StixRefRelationshipAddInput!
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

const TOOL_TYPE = 'Tool';

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
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    TOOL_TYPE,
  );
  const basicShape = {
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    tool_types: Yup.array().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const toolValidator = useSchemaEditionValidation(TOOL_TYPE, basicShape);

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
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
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

  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(tool)),
    R.assoc('killChainPhases', convertKillChainPhases(tool)),
    R.assoc('objectMarking', convertMarkings(tool)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, tool)),
    R.assoc('tool_types', tool.tool_types ?? []),
    R.assoc('references', []),
    R.pick([
      'name',
      'references',
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
          <AlertConfidenceForEntity entity={tool} />
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            askAi={true}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
              }
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
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
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Tool"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <KillChainPhasesField
            name="killChainPhases"
            required={(mandatoryAttributes.includes('killChainPhases'))}
            style={fieldSpacingContainerStyle}
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
            required={(mandatoryAttributes.includes('createdBy'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus context={context} fieldName="createdBy" />
              }
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={(mandatoryAttributes.includes('objectMarking'))}
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking" />
              }
            setFieldValue={setFieldValue}
            onChange={editor.changeMarking}
          />
          <OpenVocabField
            type="tool_types_ov"
            name="tool_types"
            label={t_i18n('Tool types')}
            required={(mandatoryAttributes.includes('tool_types'))}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={true}
            editContext={context}
          />
          {enableReferences && (
          <CommitMessage
            submitForm={submitForm}
            disabled={isSubmitting || !isValid || !dirty}
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
        entity_type
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        killChainPhases {
          id
          entity_type
          kill_chain_name
          phase_name
          x_opencti_order
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
});
