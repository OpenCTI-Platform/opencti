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
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useSchemaEditionValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const individualMutationFieldPatch = graphql`
  mutation IndividualEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    individualEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...IndividualEditionOverview_individual
        ...Individual_individual
      }
    }
  }
`;

export const individualEditionOverviewFocus = graphql`
  mutation IndividualEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    individualEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const individualMutationRelationAdd = graphql`
  mutation IndividualEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    individualEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...IndividualEditionOverview_individual
        }
      }
    }
  }
`;

const INDIVIDUAL_TYPE = 'Individual';

const individualMutationRelationDelete = graphql`
  mutation IndividualEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    individualEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...IndividualEditionOverview_individual
      }
    }
  }
`;

const IndividualEditionOverviewComponent = (props) => {
  const { individual, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    INDIVIDUAL_TYPE,
  );
  const basicShape = {
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    contact_information: Yup.string().nullable(),
    x_opencti_reliability: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const individualValidator = useSchemaEditionValidation(INDIVIDUAL_TYPE, basicShape);

  const queries = {
    fieldPatch: individualMutationFieldPatch,
    relationAdd: individualMutationRelationAdd,
    relationDelete: individualMutationRelationDelete,
    editionFocus: individualEditionOverviewFocus,
  };
  const editor = useFormEditor(individual, enableReferences, queries, individualValidator);

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
        id: individual.id,
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
      individualValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: individual.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const external = individual.external === true;
  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(individual)),
    R.assoc('objectMarking', convertMarkings(individual)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, individual)),
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
  )(individual);
  return (
    <Formik enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={individualValidator}
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
          <AlertConfidenceForEntity entity={individual} />
          <Field
            component={TextField}
            variant="standard"
            name="name"
            disabled={external}
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
            entityType="Individual"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <Field
            component={TextField}
            variant="standard"
            name="contact_information"
            label={t_i18n('Contact information')}
            required={(mandatoryAttributes.includes('contact_information'))}
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
            required={(mandatoryAttributes.includes('x_opencti_reliability'))}
            onChange={setFieldValue}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            multiple={false}
            editContext={context}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
          />
          {individual.workflowEnabled && (
          <StatusField
            name="x_opencti_workflow_id"
            type="Individual"
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
          {enableReferences && (
          <CommitMessage
            submitForm={submitForm}
            disabled={isSubmitting || !isValid || !dirty}
            setFieldValue={setFieldValue}
            open={false}
            values={values.references}
            id={individual.id}
          />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(IndividualEditionOverviewComponent, {
  individual: graphql`
      fragment IndividualEditionOverview_individual on Individual {
        id
        name
        description
        contact_information
        confidence
        entity_type
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
