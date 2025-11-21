import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { ExternalReferencesValues } from '@components/common/form/ExternalReferencesField';
import { GenericContext } from '@components/common/model/GenericContextModel';
import { OrganizationEditionOverview_organization$key } from './__generated__/OrganizationEditionOverview_organization.graphql';
import ConfidenceField from '../../common/form/ConfidenceField';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';
import StatusField from '../../common/form/StatusField';
import { useDynamicSchemaEditionValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

export const organizationEditionOverviewFragment = graphql`
  fragment OrganizationEditionOverview_organization on Organization {
    id
    name
    description
    confidence
    entity_type
    contact_information
    x_opencti_organization_type
    x_opencti_reliability
    x_opencti_score
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
`;

const organizationMutationFieldPatch = graphql`
  mutation OrganizationEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    organizationFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
      ) {
        ...OrganizationEditionOverview_organization
        ...Organization_organization
      }
  }
`;

export const organizationEditionOverviewFocus = graphql`
  mutation OrganizationEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    organizationContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const organizationMutationRelationAdd = graphql`
  mutation OrganizationEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    organizationRelationAdd(id: $id, input: $input) {       
      from {
        ...OrganizationEditionOverview_organization
      }
    }
  }
`;

const organizationMutationRelationDelete = graphql`
  mutation OrganizationEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    organizationRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
      ...OrganizationEditionOverview_organization
    }
  }
`;

const ORGANIZATION_TYPE = 'Organization';

interface OrganizationEditionOverviewComponentProps {
  organizationRef: OrganizationEditionOverview_organization$key;
  enableReferences: boolean;
  context?: readonly (GenericContext | null)[] | null;
  handleClose: () => void;
}

interface OrganizationEditionFormValues {
  message?: string;
  createdBy?: FieldOption;
  objectMarking?: FieldOption[];
  x_opencti_workflow_id: FieldOption;
  references: ExternalReferencesValues | undefined;
}

const OrganizationEditionOverview: FunctionComponent<OrganizationEditionOverviewComponentProps> = ({
  organizationRef,
  enableReferences,
  context,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const organization = useFragment(organizationEditionOverviewFragment, organizationRef);
  const { mandatoryAttributes } = useIsMandatoryAttribute(ORGANIZATION_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(1), // only sdo with allowed 1-character-length name
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    contact_information: Yup.string().nullable(),
    x_opencti_organization_type: Yup.string().nullable(),
    x_opencti_reliability: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
    x_opencti_score: Yup.number().integer(t_i18n('The value must be an integer'))
      .nullable()
      .min(0, t_i18n('The value must be greater than or equal to 0'))
      .max(100, t_i18n('The value must be less than or equal to 100')),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);
  const organizationValidator = useDynamicSchemaEditionValidation(mandatoryAttributes, basicShape);

  const queries = {
    fieldPatch: organizationMutationFieldPatch,
    relationAdd: organizationMutationRelationAdd,
    relationDelete: organizationMutationRelationDelete,
    editionFocus: organizationEditionOverviewFocus,
  };
  const editor = useFormEditor(organization as GenericData, enableReferences, queries, organizationValidator);

  const onSubmit: FormikConfig<OrganizationEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);
    const inputValues = Object.entries({
      ...otherValues,
      createdBy: values.createdBy?.value,
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    editor.fieldPatch({
      variables: {
        id: organization.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name: string, value: string | string[] | number | number[] | FieldOption | null) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as FieldOption).value;
      }
      organizationValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: organization.id,
              input: {
                key: name,
                value: finalValue ?? [null],
              },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = {
    name: organization.name,
    description: organization.description,
    contact_information: organization.contact_information,
    x_opencti_organization_type: organization.x_opencti_organization_type,
    x_opencti_reliability: organization.x_opencti_reliability,
    x_opencti_workflow_id: convertStatus(t_i18n, organization) as FieldOption,
    x_opencti_score: organization.x_opencti_score,
    createdBy: convertCreatedBy(organization) as FieldOption,
    objectMarking: convertMarkings(organization),
    references: [],
    confidence: organization.confidence,
  };

  return (
    <Formik<OrganizationEditionFormValues>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={organizationValidator}
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
          <AlertConfidenceForEntity entity={organization} />
          <Field
            component={TextField}
            variant="standard"
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
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Organization"
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
            style={fieldSpacingContainerStyle}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="contact_information" />
            }
          />
          <OpenVocabField
            label={t_i18n('Organization type')}
            type="organization_type_ov"
            name="x_opencti_organization_type"
            required={(mandatoryAttributes.includes('x_opencti_organization_type'))}
            onChange={setFieldValue}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            multiple={false}
            editContext={context}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
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
          <Field
            component={TextField}
            variant="standard"
            name="x_opencti_score"
            required={(mandatoryAttributes.includes('x_opencti_score'))}
            label={t_i18n('Score')}
            type="number"
            fullWidth={true}
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={(name: string, value: string | null) => handleSubmitField(name, (value === '' ? null : value))}
            helperText={
              <SubscriptionFocus
                context={context}
                fieldName="x_opencti_score"
              />
            }
          />
          {organization.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Organization"
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
              id={organization.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default OrganizationEditionOverview;
