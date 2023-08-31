import { Close, Edit } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import MenuItem from '@mui/material/MenuItem';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { useState } from 'react';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import { Theme } from '../../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, {
  GenericData,
} from '../../../../utils/hooks/useFormEditor';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import DashboardField from '../../common/form/DashboardField';
import { Option } from '../../common/form/ReferenceField';
import { SettingsOrganization_organization$data } from './__generated__/SettingsOrganization_organization.graphql';
import SettingsOrganizationHiddenTypesField from './SettingsOrganizationHiddenTypesField';

const useStyles = makeStyles<Theme>((theme) => ({
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  buttons: {
    marginTop: theme.spacing(2),
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
}));

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
        ...OrganizationEditionOverview_organization
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
      ...OrganizationEditionOverview_organization
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
}

interface SettingsOrganizationEditionProps {
  organization: SettingsOrganization_organization$data;
  context:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
  enableReferences?: boolean;
}

const SettingsOrganizationEdition = ({
  organization,
  context,
  enableReferences = false,
}: SettingsOrganizationEditionProps) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
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
  const [open, setOpen] = useState(false);
  const initialValues = {
    name: organization.name,
    description: organization.description,
    x_opencti_organization_type: organization.x_opencti_organization_type,
    contact_information: organization.contact_information,
    default_dashboard: organization.default_dashboard
      ? {
        value: organization.default_dashboard.id,
        label: organization.default_dashboard.name,
      }
      : null,
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
        setOpen(false);
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
    <>
      <Fab
        onClick={() => setOpen(true)}
        color="secondary"
        aria-label="Edit"
        className={classes.editButton}
      >
        <Edit />
      </Fab>
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={() => setOpen(false)}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={() => setOpen(false)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Update an organization')}</Typography>
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={organizationValidator}
            onSubmit={onSubmit}
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
                  label={t('Name')}
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
                  label={t('Description')}
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
                  label={t('Organization type')}
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
                  <MenuItem value="constituent">{t('Constituent')}</MenuItem>
                  <MenuItem value="csirt">{t('CSIRT')}</MenuItem>
                  <MenuItem value="partner">{t('Partner')}</MenuItem>
                  <MenuItem value="vendor">{t('Vendor')}</MenuItem>
                  <MenuItem value="other">{t('Other')}</MenuItem>
                </Field>
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
        </div>
      </Drawer>
    </>
  );
};

export default SettingsOrganizationEdition;
