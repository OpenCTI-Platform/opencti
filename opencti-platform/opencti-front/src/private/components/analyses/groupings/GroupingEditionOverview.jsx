import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import StatusField from '../../common/form/StatusField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

export const groupingMutationFieldPatch = graphql`
  mutation GroupingEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    groupingFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      x_opencti_graph_data
      ...GroupingEditionOverview_grouping
      ...Grouping_grouping
    }
  }
`;

export const groupingEditionOverviewFocus = graphql`
  mutation GroupingEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    groupingContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const groupingMutationRelationAdd = graphql`
  mutation GroupingEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    groupingRelationAdd(id: $id, input: $input) {
      from {
        ...GroupingEditionOverview_grouping
      }
    }
  }
`;

const GROUPING_TYPE = 'Grouping';
const groupingMutationRelationDelete = graphql`
  mutation GroupingEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    groupingRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      ...GroupingEditionOverview_grouping
    }
  }
`;

const GroupingEditionOverviewComponent = (props) => {
  const { grouping, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();

  const { mandatoryAttributes } = useIsMandatoryAttribute(
    GROUPING_TYPE,
  );
  const basicShape = {
    name: Yup.string().trim().min(2),
    confidence: Yup.number().nullable(),
    context: Yup.string(),
    description: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const groupingValidator = useSchemaEditionValidation(GROUPING_TYPE, basicShape);

  const queries = {
    fieldPatch: groupingMutationFieldPatch,
    relationAdd: groupingMutationRelationAdd,
    relationDelete: groupingMutationRelationDelete,
    editionFocus: groupingEditionOverviewFocus,
  };
  const editor = useFormEditor(
    grouping,
    enableReferences,
    queries,
    groupingValidator,
  );

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);

    editor.fieldPatch({
      variables: {
        id: grouping.id,
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
      groupingValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: grouping.id,
              input: [{ key: name, value: finalValue || '' }],
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(grouping)),
    R.assoc('objectMarking', convertMarkings(grouping)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, grouping)),
    R.assoc('references', []),
    R.pick([
      'name',
      'references',
      'context',
      'description',
      'createdBy',
      'objectMarking',
      'confidence',
      'x_opencti_workflow_id',
    ]),
  )(grouping);

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={groupingValidator}
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
            <AlertConfidenceForEntity entity={grouping} />
            <Field
              component={TextField}
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
            <ConfidenceField
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              entityType="Grouping"
              containerStyle={fieldSpacingContainerStyle}
              editContext={context}
              variant="edit"
            />
            <OpenVocabField
              label={t_i18n('Context')}
              type="grouping-context-ov"
              name="context"
              required={(mandatoryAttributes.includes('context'))}
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              variant="edit"
              multiple={false}
              editContext={context}
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
            />
            {grouping.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Grouping"
                onFocus={editor.changeFocus}
                onChange={handleSubmitField}
                setFieldValue={setFieldValue}
                style={{ marginTop: 20 }}
                helpertext={
                  <SubscriptionFocus
                    context={context}
                    fieldName="x_opencti_workflow_id"
                  />
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
                <SubscriptionFocus
                  context={context}
                  fieldname="objectMarking"
                />
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
                id={grouping.id}
              />
            )}
          </Form>
        </div>
      )}
    </Formik>
  );
};

export default createFragmentContainer(GroupingEditionOverviewComponent, {
  grouping: graphql`
    fragment GroupingEditionOverview_grouping on Grouping {
      id
      name
      description
      context
      confidence
      entity_type
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
});
