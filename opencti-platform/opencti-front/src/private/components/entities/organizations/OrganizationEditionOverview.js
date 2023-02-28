import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { useYupSchemaBuilder } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';

const organizationMutationFieldPatch = graphql`
  mutation OrganizationEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    organizationEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...OrganizationEditionOverview_organization
        ...Organization_organization
      }
    }
  }
`;

export const organizationEditionOverviewFocus = graphql`
  mutation OrganizationEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    organizationEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const organizationMutationRelationAdd = graphql`
  mutation OrganizationEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    organizationEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...OrganizationEditionOverview_organization
        }
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
    organizationEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...OrganizationEditionOverview_organization
      }
    }
  }
`;

const OrganizationEditionOverviewComponent = (props) => {
  const { organization, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    contact_information: Yup.string().nullable(),
    x_opencti_organization_type: Yup.string().nullable(),
    x_opencti_reliability: Yup.string().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const organizationValidator = useYupSchemaBuilder('Organization', basicShape);

  const queries = {
    fieldPatch: organizationMutationFieldPatch,
    relationAdd: organizationMutationRelationAdd,
    relationDelete: organizationMutationRelationDelete,
    editionFocus: organizationEditionOverviewFocus,
  };
  const editor = useFormEditor(organization, enableReferences, queries, organizationValidator);

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
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: organization.id,
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
      organizationValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: organization.id,
              input: {
                key: name,
                value: finalValue ?? '',
              },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(organization)),
    R.assoc('objectMarking', convertMarkings(organization)),
    R.assoc('x_opencti_workflow_id', convertStatus(t, organization)),
    R.assoc('references', []),
    R.pick([
      'name',
      'description',
      'contact_information',
      'x_opencti_organization_type',
      'x_opencti_reliability',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(organization);
  return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={organizationValidator}
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
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
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
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            <Field
              component={TextField}
              variant="standard"
              name="contact_information"
              label={t('Contact information')}
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
            <Field
              component={SelectField}
              variant="standard"
              name="x_opencti_organization_type"
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
              label={t('Organization type')}
              fullWidth={true}
              inputProps={{
                name: 'x_opencti_organization_type',
                id: 'x_opencti_organization_type',
              }}
              containerstyle={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus context={context} fieldName="x_opencti_organization_type" />
              }
            >
              <MenuItem value="constituent">{t('Constituent')}</MenuItem>
              <MenuItem value="csirt">{t('CSIRT')}</MenuItem>
              <MenuItem value="partner">{t('Partner')}</MenuItem>
              <MenuItem value="vendor">{t('Vendor')}</MenuItem>
              <MenuItem value="other">{t('Other')}</MenuItem>
            </Field>
            <Field
              component={SelectField}
              variant="standard"
              name="x_opencti_reliability"
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
              label={t('Reliability')}
              fullWidth={true}
              inputProps={{
                name: 'x_opencti_reliability',
                id: 'x_opencti_reliability',
              }}
              containerstyle={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus context={context} fieldName="x_opencti_reliability" />
              }
            >
              <MenuItem value="A">{t('reliability_A')}</MenuItem>
              <MenuItem value="B">{t('reliability_B')}</MenuItem>
              <MenuItem value="C">{t('reliability_C')}</MenuItem>
              <MenuItem value="D">{t('reliability_D')}</MenuItem>
              <MenuItem value="E">{t('reliability_E')}</MenuItem>
              <MenuItem value="F">{t('reliability_F')}</MenuItem>
            </Field>
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
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdBy" />
              }
              onChange={editor.changeCreated}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus context={context} fieldname="objectMarking" />
              }
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

export default createFragmentContainer(OrganizationEditionOverviewComponent, {
  organization: graphql`
      fragment OrganizationEditionOverview_organization on Organization {
        id
        name
        description
        contact_information
        x_opencti_organization_type
        x_opencti_reliability
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
