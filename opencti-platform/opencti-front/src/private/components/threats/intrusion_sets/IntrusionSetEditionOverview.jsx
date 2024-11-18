import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const intrusionSetMutationFieldPatch = graphql`
  mutation IntrusionSetEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    intrusionSetEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...IntrusionSetEditionOverview_intrusionSet
        ...IntrusionSet_intrusionSet
      }
    }
  }
`;

export const intrusionSetEditionOverviewFocus = graphql`
  mutation IntrusionSetEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    intrusionSetEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

export const intrusionSetMutationRelationAdd = graphql`
  mutation IntrusionSetEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    intrusionSetEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...IntrusionSetEditionOverview_intrusionSet
        }
      }
    }
  }
`;

export const intrusionSetMutationRelationDelete = graphql`
  mutation IntrusionSetEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    intrusionSetEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...IntrusionSetEditionOverview_intrusionSet
      }
    }
  }
`;

const IntrusionSetEditionOverviewComponent = (props) => {
  const { intrusionSet, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();
  const theme = useTheme();

  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    confidence: Yup.number().nullable(),
    description: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const intrusionSetValidator = useSchemaEditionValidation(
    'Intrusion-Set',
    basicShape,
  );

  const queries = {
    fieldPatch: intrusionSetMutationFieldPatch,
    relationAdd: intrusionSetMutationRelationAdd,
    relationDelete: intrusionSetMutationRelationDelete,
    editionFocus: intrusionSetEditionOverviewFocus,
  };
  const editor = useFormEditor(
    intrusionSet,
    enableReferences,
    queries,
    intrusionSetValidator,
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
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: intrusionSet.id,
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
      intrusionSetValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: intrusionSet.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(intrusionSet)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, intrusionSet)),
    R.assoc('objectMarking', convertMarkings(intrusionSet)),
    R.assoc('references', []),
    R.pick([
      'name',
      'references',
      'confidence',
      'description',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(intrusionSet);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={intrusionSetValidator}
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
          <AlertConfidenceForEntity entity={intrusionSet} />
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
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Intrusion-Set"
            containerStyle={fieldSpacingContainerStyle}
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
          {intrusionSet.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Intrusion-Set"
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
              id={intrusionSet.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(IntrusionSetEditionOverviewComponent, {
  intrusionSet: graphql`
    fragment IntrusionSetEditionOverview_intrusionSet on IntrusionSet {
      id
      name
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
});
