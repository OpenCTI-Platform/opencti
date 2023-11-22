import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import { useSchemaEditionValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

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
    $input: StixRefRelationshipAddInput!
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

const COURSE_OF_ACTION_TYPE = 'Course-Of-Action';

const CourseOfActionEditionOverviewComponent = (props) => {
  const { courseOfAction, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    COURSE_OF_ACTION_TYPE,
  );
  const basicShape = {
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    x_opencti_threat_hunting: Yup.string().nullable(),
    x_opencti_log_sources: Yup.string().nullable(),
    x_mitre_id: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const courseOfActionValidator = useSchemaEditionValidation(
    COURSE_OF_ACTION_TYPE,
    basicShape,
  );

  const queries = {
    fieldPatch: courseOfActionMutationFieldPatch,
    relationAdd: courseOfActionMutationRelationAdd,
    relationDelete: courseOfActionMutationRelationDelete,
    editionFocus: courseOfActionEditionOverviewFocus,
  };
  const editor = useFormEditor(
    courseOfAction,
    enableReferences,
    queries,
    courseOfActionValidator,
  );

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('confidence', parseInt(values.confidence, 10)),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: courseOfAction.id,
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
      if (name === 'x_opencti_log_sources') {
        finalValue = value && value.length > 0 ? R.split('\n', value) : [];
      }
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      courseOfActionValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: courseOfAction.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };
  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(courseOfAction)),
    R.assoc('objectMarking', convertMarkings(courseOfAction)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, courseOfAction)),
    R.assoc('references', []),
    R.assoc(
      'x_opencti_log_sources',
      R.join('\n', courseOfAction.x_opencti_log_sources ? courseOfAction.x_opencti_log_sources : []),
    ),
    R.pick([
      'name',
      'description',
      'references',
      'x_mitre_id',
      'x_opencti_threat_hunting',
      'x_opencti_log_sources',
      'createdBy',
      'objectMarking',
      'confidence',
      'x_opencti_workflow_id',
      'x_mitre_id',
    ]),
  )(courseOfAction);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={courseOfActionValidator}
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
          <AlertConfidenceForEntity entity={courseOfAction} />
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <Field
            component={TextField}
            name="x_mitre_id"
            label={t_i18n('External ID')}
            required={(mandatoryAttributes.includes('x_mitre_id'))}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="x_mitre_id" />
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
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Course-Of-Action"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <Field
            component={MarkdownField}
            name="x_opencti_threat_hunting"
            label={t_i18n('Threat hunting techniques')}
            required={(mandatoryAttributes.includes('x_opencti_threat_hunting'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
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
            name="x_opencti_log_sources"
            label={t_i18n('Log sources (1 / line)')}
            required={(mandatoryAttributes.includes('x_opencti_log_sources'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
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
      confidence
      entity_type
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
