import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React from 'react';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import GroupField from '@components/common/form/GroupField';
import { GenericContext } from '@components/common/model/GenericContextModel';
import OpenVocabField from '@components/common/form/OpenVocabField';
import EEField from '@components/common/entreprise_edition/EEField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import DashboardField from '../../common/form/DashboardField';
import { SettingsOrganization_organization$data } from './__generated__/SettingsOrganization_organization.graphql';
import SettingsOrganizationHiddenTypesField from './SettingsOrganizationHiddenTypesField';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

const organizationMutationFieldPatch = graphql`
  mutation SettingsOrganizationEditionMutation(
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
      ...SettingsOrganization_organization
    }
  }
`;

export const organizationEditionOverviewFocus = graphql`
  mutation SettingsOrganizationEditionFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    organizationContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const organizationMutationRelationAdd = graphql`
  mutation SettingsOrganizationEditionRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    organizationRelationAdd(id: $id, input: $input) {
      from {
        ...SettingsOrganization_organization
      }
    }
  }
`;

const organizationMutationRelationDelete = graphql`
  mutation SettingsOrganizationEditionRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    organizationRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
      ...SettingsOrganization_organization
    }
  }
`;

interface SettingsOrganizationFormValues {
  name: string;
  description: string | null;
  x_opencti_organization_type: string | null;
  contact_information: string | null;
  default_dashboard: FieldOption | null;
  message?: string;
  references?: FieldOption[];
  grantable_groups: { label: string; value: string; }[];
}

interface SettingsOrganizationEditionProps {
  organization: SettingsOrganization_organization$data
  context?: readonly (GenericContext | null)[] | null;
  enableReferences?: boolean
}

export const convertGrantableGroups = (organization: SettingsOrganization_organization$data) => (organization?.grantable_groups ?? []).map((n) => ({
  label: n.name,
  value: n.id,
}));

const UpdateSettingsOrganizationControlledDial = (props: DrawerControlledDialProps) => (
  <EditEntityControlledDial
    style={{ float: 'right' }}
    {...props}
  />
);

const SettingsOrganizationEdition = ({
  organization,
  context,
  enableReferences = false,
}: SettingsOrganizationEditionProps) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();

  const basicShape = {
    name: Yup.string().trim().min(1).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    contact_information: Yup.string().nullable(),
    x_opencti_organization_type: Yup.string().nullable(),
  };
  const organizationValidator = useSchemaEditionValidation(
    'Organization',
    basicShape,
  );
  const queries = {
    fieldPatch: organizationMutationFieldPatch,
    relationAdd: organizationMutationRelationAdd,
    relationDelete: organizationMutationRelationDelete,
    editionFocus: organizationEditionOverviewFocus,
  };
  const editor = useFormEditor(
    organization as unknown as GenericData,
    enableReferences,
    queries,
    organizationValidator,
  );
  const initialValues: SettingsOrganizationFormValues = {
    name: organization.name,
    description: organization.description ?? null,
    x_opencti_organization_type: organization.x_opencti_organization_type ?? null,
    contact_information: organization.contact_information ?? null,
    default_dashboard: organization.default_dashboard
      ? {
        value: organization.default_dashboard.id,
        label: organization.default_dashboard.name,
      }
      : null,
    grantable_groups: convertGrantableGroups(organization),
  };
  const onSubmit: FormikConfig<SettingsOrganizationFormValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);
    const inputValues = Object.entries(otherValues).map(([key, value]) => ({
      key,
      value: adaptFieldValue(value),
    }));
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
      },
    });
  };
  const handleSubmitField = (name: string, value: string | string[]) => {
    if (!enableReferences) {
      organizationValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: organization.id,
              input: {
                key: name,
                value: value ?? '',
              },
            },
          });
        })
        .catch(() => false);
    }
  };
  return (
    <Drawer
      title={t_i18n('Update the organization')}
      context={context}
      controlledDial={UpdateSettingsOrganizationControlledDial}
    >
      {({ onClose }) => (
        <Formik<SettingsOrganizationFormValues>
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={organizationValidator}
          onSubmit={(values, formikHelpers) => {
            onSubmit(values, formikHelpers);
            onClose();
          }}
        >
          {({
            submitForm,
            isSubmitting,
            isValid,
            dirty,
            setFieldValue,
            values,
          }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
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
                  <SubscriptionFocus
                    context={context}
                    fieldName="description"
                  />
                }
              />
              <OpenVocabField
                label={t_i18n('Organization type')}
                type="organization_type_ov"
                name="x_opencti_organization_type"
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
                name="contact_information"
                label={t_i18n('Contact information')}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={{ marginTop: 20 }}
                onFocus={editor.changeFocus}
                onSubmit={handleSubmitField}
                helperText={
                  <SubscriptionFocus
                    context={context}
                    fieldName="contact_information"
                  />
                }
              />
              <DashboardField
                onChange={editor.changeField}
                context={context}
              />
              <SettingsOrganizationHiddenTypesField organizationData={organization} />
              <EEField featureLabel={'Organization sharing'}>
                <GroupField
                  name="grantable_groups"
                  label={'Grantable groups by Organization administrators'}
                  multiple={true}
                  onChange={editor.changeGrantableGroups}
                  style={{ marginTop: 20 }}
                  disabled={!isEnterpriseEdition}
                />
              </EEField>
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
      )}
    </Drawer>
  );
};

export default SettingsOrganizationEdition;
