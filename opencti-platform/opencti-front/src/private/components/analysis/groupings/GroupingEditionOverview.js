import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import { commitMutation } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import MarkDownField from '../../../../components/MarkDownField';
import StatusField from '../../common/form/StatusField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

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
    $input: StixMetaRelationshipAddInput
  ) {
    groupingRelationAdd(id: $id, input: $input) {
      from {
        ...GroupingEditionOverview_grouping
      }
    }
  }
`;

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

const groupingValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  published: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .required(t('This field is required')),
  context: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  confidence: Yup.number(),
  x_opencti_workflow_id: Yup.object(),
});

const GroupingEditionOverviewComponent = (props) => {
  const { grouping, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();
  const handleChangeFocus = (name) => commitMutation({
    mutation: groupingEditionOverviewFocus,
    variables: {
      id: grouping.id,
      input: {
        focusOn: name,
      },
    },
  });
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
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: groupingMutationFieldPatch,
      variables: {
        id: grouping.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      setSubmitting,
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
      groupingValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: groupingMutationFieldPatch,
            variables: {
              id: grouping.id,
              input: {
                key: name,
                value: finalValue,
              },
            },
          });
        })
        .catch(() => false);
    }
  };
  const handleChangeCreatedBy = (name, value) => {
    if (!enableReferences) {
      commitMutation({
        mutation: groupingMutationFieldPatch,
        variables: {
          id: grouping.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  };
  const handleChangeObjectMarking = (name, values) => {
    if (!enableReferences) {
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(grouping);
      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);
      if (added.length > 0) {
        commitMutation({
          mutation: groupingMutationRelationAdd,
          variables: {
            id: grouping.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: groupingMutationRelationDelete,
          variables: {
            id: grouping.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };
  const createdBy = convertCreatedBy(grouping);
  const objectMarking = convertMarkings(grouping);
  const status = convertStatus(t, grouping);
  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.pick([
      'name',
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
      validationSchema={groupingValidation(t)}
      onSubmit={onSubmit}
    >
      {({
        submitForm,
        isSubmitting,

        setFieldValue,
        values,
      }) => (
        <div>
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <ConfidenceField
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              containerStyle={fieldSpacingContainerStyle}
              editContext={context}
              variant="edit"
              entityType="Grouping"
            />
            <OpenVocabField
              label={t('Context')}
              type="grouping-context-ov"
              name="context"
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              variant="edit"
              multiple={false}
              editContext={context}
            />
            <Field
              component={MarkDownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
            />
            {grouping.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Grouping"
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
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
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdBy" />
              }
              onChange={handleChangeCreatedBy}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldname="objectMarking"
                />
              }
              onChange={handleChangeObjectMarking}
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                open={false}
                setFieldValue={setFieldValue}
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
