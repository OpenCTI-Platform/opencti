import MenuItem from '@mui/material/MenuItem';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React from 'react';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import GroupField from '@components/common/form/GroupField';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { GenericContext } from '@components/common/model/GenericContextModel';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import DashboardField from '../../common/form/DashboardField';
import { Option } from '../../common/form/ReferenceField';
import { SettingsOrganization_organization$data } from './__generated__/SettingsOrganization_organization.graphql';
import SettingsOrganizationHiddenTypesField from './SettingsOrganizationHiddenTypesField';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

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
  default_dashboard: Option | null;
  message?: string;
  references?: Option[];
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

const SettingsOrganizationEdition = ({
  organization,
  context,
  enableReferences = false,
}: SettingsOrganizationEditionProps) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();

  const basicShape = {
    name: Yup.string().min(2).required(t_i18n('This field is required')),
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
  const handleSubmitField = (key: string, value: string) => {
    if (!enableReferences) {
      organizationValidator
        .validateAt(key, { [key]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: organization.id,
              input: {
                key,
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
      variant={DrawerVariant.updateWithPanel}
      context={context}
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
            <Form style={{ margin: '20px 0 20px 0' }}>
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
              <Field
                component={SelectField}
                variant="standard"
                name="x_opencti_organization_type"
                onChange={handleSubmitField}
                label={t_i18n('Organization type')}
                fullWidth={true}
                inputProps={{
                  name: 'x_opencti_organization_type',
                  id: 'x_opencti_organization_type',
                }}
                containerstyle={fieldSpacingContainerStyle}
                helpertext={
                  <SubscriptionFocus
                    context={context}
                    fieldName="x_opencti_organization_type"
                  />
                }
              >
                <MenuItem value="constituent">{t_i18n('Constituent')}</MenuItem>
                <MenuItem value="csirt">{t_i18n('CSIRT')}</MenuItem>
                <MenuItem value="partner">{t_i18n('Partner')}</MenuItem>
                <MenuItem value="vendor">{t_i18n('Vendor')}</MenuItem>
                <MenuItem value="other">{t_i18n('Other')}</MenuItem>
              </Field>
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
              <GroupField
                name="grantable_groups"
                label={<>{t_i18n('Grantable groups by Organization administrators')}<EEChip feature={t_i18n('Organization sharing')} /></>}
                multiple={true}
                onChange={editor.changeGrantableGroups}
                containerStyle={{ width: '100%', backgroundColor: 'red' }}
                style={{ marginTop: 20 }}
                disabled={!isEnterpriseEdition}
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
      )}
    </Drawer>
  );
};

export default SettingsOrganizationEdition;
