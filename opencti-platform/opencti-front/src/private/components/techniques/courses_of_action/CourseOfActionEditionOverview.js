import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';

const courseOfActionMutationFieldPatch = graphql`
  mutation CourseOfActionEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    courseOfActionEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...CourseOfActionEditionOverview_courseOfAction
        ...CourseOfAction_courseOfAction
      }
    }
  }
`;

export const courseOfActionEditionOverviewFocus = graphql`
  mutation CourseOfActionEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    courseOfActionEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const courseOfActionMutationRelationAdd = graphql`
  mutation CourseOfActionEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    courseOfActionEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...CourseOfActionEditionOverview_courseOfAction
        }
      }
    }
  }
`;

const courseOfActionMutationRelationDelete = graphql`
  mutation CourseOfActionEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    courseOfActionEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...CourseOfActionEditionOverview_courseOfAction
      }
    }
  }
`;

const courseOfActionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  x_opencti_threat_hunting: Yup.string().nullable(),
  x_opencti_log_sources: Yup.string().nullable(),
  references: Yup.array().required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
  x_mitre_id: Yup.string().nullable(),
});

const CourseOfActionEditionOverviewComponent = (props) => {
  const { courseOfAction, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const handleChangeFocus = (name) => commitMutation({
    mutation: courseOfActionEditionOverviewFocus,
    variables: {
      id: courseOfAction.id,
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
      mutation: courseOfActionMutationFieldPatch,
      variables: {
        id: courseOfAction.id,
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
      if (name === 'x_opencti_log_sources') {
        finalValue = R.split('\n', value);
      }
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      courseOfActionValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: courseOfActionMutationFieldPatch,
            variables: {
              id: courseOfAction.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };
  const handleChangeCreatedBy = (name, value) => {
    if (!enableReferences) {
      commitMutation({
        mutation: courseOfActionMutationFieldPatch,
        variables: {
          id: courseOfAction.id,
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
      )(courseOfAction);

      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);

      if (added.length > 0) {
        commitMutation({
          mutation: courseOfActionMutationRelationAdd,
          variables: {
            id: courseOfAction.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }

      if (removed.length > 0) {
        commitMutation({
          mutation: courseOfActionMutationRelationDelete,
          variables: {
            id: courseOfAction.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const createdBy = convertCreatedBy(courseOfAction);
  const objectMarking = convertMarkings(courseOfAction);
  const status = convertStatus(t, courseOfAction);
  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.pick([
      'name',
      'description',
      'x_mitre_id',
      'x_opencti_threat_hunting',
      'x_opencti_log_sources',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
      'x_mitre_id',
    ]),
  )(courseOfAction);
  return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={courseOfActionValidation(t)}
        onSubmit={onSubmit}
      >
        {({
          submitForm,
          isSubmitting,
          setFieldValue,
          values,
        }) => (
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
            <Field
              component={TextField}
              variant="standard"
              name="x_mitre_id"
              label={t('External ID')}
              fullWidth={true}
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="x_mitre_id" />
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
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            <Field
              component={MarkDownField}
              name="x_opencti_threat_hunting"
              label={t('Threat hunting techniques')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_opencti_threat_hunting"
                />
              }
            />
            <Field
              component={TextField}
              variant="standard"
              name="x_opencti_log_sources"
              label={t('Log sources (1 / line)')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_opencti_log_sources"
                />
              }
            />
            {courseOfAction.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Course-Of-Action"
                onFocus={handleChangeFocus}
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
                setFieldValue={setFieldValue}
                open={false}
                values={values.references}
                id={courseOfAction.id}
              />
            )}
          </Form>
        )}
      </Formik>
  );
};

export default createFragmentContainer(CourseOfActionEditionOverviewComponent, {
  courseOfAction: graphql`
      fragment CourseOfActionEditionOverview_courseOfAction on CourseOfAction {
        id
        name
        description
        x_opencti_threat_hunting
        x_opencti_log_sources
        x_mitre_id
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
