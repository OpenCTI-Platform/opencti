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
import OpenVocabField from '../../common/form/OpenVocabField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const systemMutationFieldPatch = graphql`
  mutation SystemEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    systemEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...SystemEditionOverview_system
        ...System_system
      }
    }
  }
`;

export const systemEditionOverviewFocus = graphql`
  mutation SystemEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    systemEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const systemMutationRelationAdd = graphql`
  mutation SystemEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    systemEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...SystemEditionOverview_system
        }
      }
    }
  }
`;

const systemMutationRelationDelete = graphql`
  mutation SystemEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    systemEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...SystemEditionOverview_system
      }
    }
  }
`;

const SystemEditionOverviewComponent = (props) => {
  const { system, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();

  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    contact_information: Yup.string().nullable(),
    x_opencti_reliability: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const systemValidator = useSchemaEditionValidation('System', basicShape);

  const queries = {
    fieldPatch: systemMutationFieldPatch,
    relationAdd: systemMutationRelationAdd,
    relationDelete: systemMutationRelationDelete,
    editionFocus: systemEditionOverviewFocus,
  };
  const editor = useFormEditor(system, enableReferences, queries, systemValidator);

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
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: system.id,
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
      systemValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: system.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const external = system.external === true;
  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(system)),
    R.assoc('objectMarking', convertMarkings(system)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, system)),
    R.assoc('references', []),
    R.pick([
      'name',
      'references',
      'description',
      'contact_information',
      'x_opencti_reliability',
      'createdBy',
      'objectMarking',
      'confidence',
      'x_opencti_workflow_id',
    ]),
  )(system);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={systemValidator}
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
        <Form>
          <AlertConfidenceForEntity entity={system} />
          <Field
            component={TextField}
            variant="standard"
            name="name"
            disabled={external}
            label={t_i18n('Name')}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
              }
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
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="System"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <Field
            component={TextField}
            variant="standard"
            name="contact_information"
            label={t_i18n('Contact information')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="contact_information" />
              }
          />
          <OpenVocabField
            label={t_i18n('Reliability')}
            type="reliability_ov"
            name="x_opencti_reliability"
            onChange={setFieldValue}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            multiple={false}
            editContext={context}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
          />
          {system.workflowEnabled && (
          <StatusField
            name="x_opencti_workflow_id"
            type="System"
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
            id={system.id}
          />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(SystemEditionOverviewComponent, {
  system: graphql`
      fragment SystemEditionOverview_system on System {
        id
        name
        description
        confidence
        entity_type
        contact_information
        x_opencti_reliability
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
