import React, { useContext, useRef } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { FileUploadOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '@mui/styles';
import ToggleButton from '@mui/material/ToggleButton';
import VisuallyHiddenInput from '../common/VisuallyHiddenInput';
import Drawer from '../common/drawer/Drawer';
import { useFormatter } from '../../../components/i18n';
import { handleError } from '../../../relay/environment';
import TextField from '../../../components/TextField';
import MarkdownField from '../../../components/fields/MarkdownField';
import { resolveLink } from '../../../utils/Entity';
import { insertNode } from '../../../utils/store';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../components/CreateEntityControlledDial';
import { isNotEmptyField } from '../../../utils/utils';
import GradientButton from '../../../components/GradientButton';
import { UserContext } from '../../../utils/hooks/useAuth';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const workspaceMutation = graphql`
  mutation WorkspaceCreationMutation($input: WorkspaceAddInput!) {
    workspaceAdd(input: $input) {
      id
      ...WorkspacesLine_node
    }
  }
`;

export const importMutation = graphql`
  mutation WorkspaceCreationImportMutation($file: Upload!) {
    workspaceConfigurationImport(file: $file)
  }
`;

const workspaceValidation = (t_i18n) => Yup.object().shape({
  name: Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters')).required(t_i18n('This field is required')),
  description: Yup.string().nullable(),
});

const WorkspaceCreation = ({ paginationOptions, type }) => {
  const classes = useStyles();
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const inputRef = useRef();
  const { settings, isXTMHubAccessible } = useContext(UserContext);
  const importFromHubUrl = isNotEmptyField(settings?.platform_xtmhub_url)
    ? `${settings.platform_xtmhub_url}/redirect/octi_custom_dashboards?platform_id=${settings.id}`
    : '';

  const [commitImportMutation] = useApiMutation(importMutation);
  const [commitCreationMutation] = useApiMutation(workspaceMutation);
  const navigate = useNavigate();

  const handleImport = (event) => {
    const importedFile = event.target.files[0];
    commitImportMutation({
      variables: { file: importedFile },
      onCompleted: (data) => {
        inputRef.current.value = null; // Reset the input uploader ref
        navigate(
          `${resolveLink('Dashboard')}/${data.workspaceConfigurationImport}`,
        );
      },
      onError: (error) => {
        inputRef.current.value = null; // Reset the input uploader ref
        handleError(error);
      },
    });
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    commitCreationMutation({
      variables: {
        input: {
          ...values,
          type,
        },
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_workspaces',
          paginationOptions,
          'workspaceAdd',
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  const createInvestigationButton = (props) => (
    <CreateEntityControlledDial entityType='Investigation' {...props} />
  );

  const createDashboardButton = (props) => (
    <>
      <ToggleButton
        value="import"
        size="small"
        onClick={() => inputRef.current?.click()}
        sx={{ marginLeft: theme.spacing(1) }}
        data-testid='ImportDashboard'
        title={t_i18n('Import dashboard')}
      >
        <FileUploadOutlined fontSize="small" color={'primary'} />
      </ToggleButton>
      {isXTMHubAccessible && isNotEmptyField(importFromHubUrl) && (
        <GradientButton
          size="small"
          sx={{ marginLeft: theme.spacing(1) }}
          href={importFromHubUrl}
          target="_blank"
          title={t_i18n('Import from Hub')}
        >
          {t_i18n('Import from Hub')}
        </GradientButton>
      )}
      <CreateEntityControlledDial entityType='Dashboard' {...props} />
    </>
  );

  return (
    <>
      <VisuallyHiddenInput type="file" accept={'application/JSON'} ref={inputRef} onChange={handleImport} />
      <Drawer
        title={t_i18n(`Create ${type}`)}
        controlledDial={(type === 'dashboard')
          ? createDashboardButton
          : createInvestigationButton
        }
      >
        {({ onClose }) => (
          <Formik
            initialValues={{
              name: '',
              description: '',
            }}
            validationSchema={workspaceValidation(t_i18n)}
            onSubmit={onSubmit}
            onReset={onClose}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <Field
                  component={TextField}
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth={true}
                />
                <Field
                  component={MarkdownField}
                  name="description"
                  label={t_i18n('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 20 }}
                />
                <div className={classes.buttons}>
                  <Button
                    variant="contained"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t_i18n('Create')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        )}
      </Drawer>
    </>
  );
};

export default WorkspaceCreation;
