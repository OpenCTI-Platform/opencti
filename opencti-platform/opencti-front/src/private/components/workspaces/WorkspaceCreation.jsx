import React, { useRef } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { CloudUploadOutlined, InsertChartOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom';
import { SpeedDial, SpeedDialAction, SpeedDialIcon } from '@mui/material';
import useHelper from '../../../utils/hooks/useHelper';
import VisuallyHiddenInput from '../common/VisuallyHiddenInput';
import Drawer, { DrawerVariant } from '../common/drawer/Drawer';
import { useFormatter } from '../../../components/i18n';
import { handleError } from '../../../relay/environment';
import TextField from '../../../components/TextField';
import MarkdownField from '../../../components/fields/MarkdownField';
import { resolveLink } from '../../../utils/Entity';
import { insertNode } from '../../../utils/store';
import useApiMutation from '../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1100,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  speedDialButton: {
    backgroundColor: theme.palette.primary.main,
    color: theme.palette.primary.contrastText,
    '&:hover': {
      backgroundColor: theme.palette.primary.main,
    },
  },
}));

const workspaceMutation = graphql`
  mutation WorkspaceCreationMutation($input: WorkspaceAddInput!) {
    workspaceAdd(input: $input) {
      id
      ...WorkspaceLine_node
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
  const { t_i18n } = useFormatter();
  const inputRef = useRef();
  const { isFeatureEnable } = useHelper();
  const FAB_REPLACED = isFeatureEnable('FAB_REPLACEMENT');
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

  const createInvestigationButton = FAB_REPLACED ? ({ onOpen }) => (
    <Button
      color='primary'
      size='small'
      variant='contained'
      disableElevation
      onClick={onOpen}
    >
      {t_i18n('Create an investigation')}
    </Button>
  ) : undefined;

  const createDashboardButton = FAB_REPLACED ? ({ onOpen }) => (
    <div>
      <Button
        color='primary'
        size='small'
        variant='contained'
        disableElevation
        onClick={onOpen}
        data-testid='CreateDashboard'
      >
        {t_i18n('Create dashboard')}
      </Button>
      <Button
        color='primary'
        size='small'
        variant='contained'
        disableElevation
        onClick={() => inputRef.current?.click()}
        sx={{ marginLeft: '3px' }}
        data-testid='ImportDashboard'
      >
        {t_i18n('Import dashboard')}
      </Button>
    </div>
  ) : ({ onOpen }) => (
    <SpeedDial
      className={classes.createButton}
      ariaLabel="Create"
      icon={<SpeedDialIcon />}
      FabProps={{ color: 'primary' }}
    >
      <SpeedDialAction
        title={t_i18n('Create dashboard')}
        icon={<InsertChartOutlined />}
        tooltipTitle={t_i18n('Create dashboard')}
        onClick={onOpen}
        FabProps={{ classes: { root: classes.speedDialButton } }}
      />
      <SpeedDialAction
        title={t_i18n('Import dashboard')}
        icon={<CloudUploadOutlined />}
        tooltipTitle={t_i18n('Import dashboard')}
        onClick={() => inputRef.current?.click()}
        FabProps={{ classes: { root: classes.speedDialButton } }}
      />
    </SpeedDial>);

  return (
    <>
      <VisuallyHiddenInput type="file" accept={'application/JSON'} ref={inputRef} onChange={handleImport} />
      <Drawer
        title={t_i18n(`Create ${type}`)}
        variant={FAB_REPLACED || type === 'dashboard' ? undefined : DrawerVariant.create}
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
              <Form style={{ margin: '20px 0 20px 0' }}>
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
