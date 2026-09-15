import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import SelectField from '../../../../components/fields/SelectField';
import TextField from '../../../../components/TextField';
import MenuItem from '@mui/material/MenuItem';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useDynamicSchemaEditionValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const citizenshipDocumentMutationFieldPatch = graphql`
  mutation CitizenshipDocumentEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    citizenshipDocumentEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...CitizenshipDocumentEditionOverview_citizenshipDocument
        ...CitizenshipDocument_citizenshipDocument
      }
    }
  }
`;

export const citizenshipDocumentEditionOverviewFocus = graphql`
  mutation CitizenshipDocumentEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    citizenshipDocumentEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const citizenshipDocumentMutationRelationAdd = graphql`
  mutation CitizenshipDocumentEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    citizenshipDocumentEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...CitizenshipDocumentEditionOverview_citizenshipDocument
        }
      }
    }
  }
`;

const citizenshipDocumentMutationRelationDelete = graphql`
  mutation CitizenshipDocumentEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    citizenshipDocumentEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...CitizenshipDocumentEditionOverview_citizenshipDocument
      }
    }
  }
`;

const CITIZENSHIP_DOCUMENT_TYPE = 'Citizenship-Document';

const CitizenshipDocumentEditionOverviewComponent = (props) => {
  const { citizenshipDocument, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(CITIZENSHIP_DOCUMENT_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    contact_information: Yup.string().nullable(),
    x_opencti_reliability: Yup.string().nullable(),
    x_opencti_citizenship_document_type: Yup.string().nullable(),
    x_opencti_citizenship_document_id: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);
  const citizenshipDocumentValidator = useDynamicSchemaEditionValidation(mandatoryAttributes, basicShape);

  const queries = {
    fieldPatch: citizenshipDocumentMutationFieldPatch,
    relationAdd: citizenshipDocumentMutationRelationAdd,
    relationDelete: citizenshipDocumentMutationRelationDelete,
    editionFocus: citizenshipDocumentEditionOverviewFocus,
  };
  const editor = useFormEditor(citizenshipDocument, enableReferences, queries, citizenshipDocumentValidator);

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
        id: citizenshipDocument.id,
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
      citizenshipDocumentValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: citizenshipDocument.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const external = citizenshipDocument.external === true;
  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(citizenshipDocument)),
    R.assoc('objectMarking', convertMarkings(citizenshipDocument)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, citizenshipDocument)),
    R.assoc('references', []),
    R.pick([
      'name',
      'references',
      'description',
      'contact_information',
      'x_opencti_reliability',
      'x_opencti_citizenship_document_type',
      'x_opencti_citizenship_document_id',
      'createdBy',
      'objectMarking',
      'confidence',
      'x_opencti_workflow_id',
    ]),
  )(citizenshipDocument);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={citizenshipDocumentValidator}
      validateOnChange={true}
      validateOnBlur={true}
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
          <AlertConfidenceForEntity entity={citizenshipDocument} />
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
            component={SelectField}
            variant="standard"
            as="select"
            name="x_opencti_citizenship_document_type"
            label={t_i18n('Document type')}
            multiple={false}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            containerStyle={fieldSpacingContainerStyle}
          >
            <MenuItem
              key="passport"
              value="passport"
            >
              Passport
            </MenuItem>
            <MenuItem
              key="national id"
              value="national id"
            >
              National ID
            </MenuItem>
            <MenuItem
              key="citizenship document"
              value="citizenship document"
            >
              Citizenship Documents
            </MenuItem>
          </Field>
          <Field
            component={TextField}
            variant="standard"
            name="x_opencti_citizenship_document_id"
            label={t_i18n('Document ID')}
            fullWidth={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="x_opencti_citizenship_document_id" />
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
            uploadEntityId={citizenshipDocument.id}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="CitizenshipDocument"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
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
          {citizenshipDocument.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="CitizenshipDocument"
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
              id={citizenshipDocument.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(CitizenshipDocumentEditionOverviewComponent, {
  citizenshipDocument: graphql`
      fragment CitizenshipDocumentEditionOverview_citizenshipDocument on CitizenshipDocument {
        id
        name
        description
        contact_information
        confidence
        entity_type
        x_opencti_citizenship_document_type
        x_opencti_citizenship_document_id
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
