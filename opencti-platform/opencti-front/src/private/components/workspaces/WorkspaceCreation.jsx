import React, { useRef } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import { SpeedDialIcon } from '@mui/material';
import SpeedDial from '@mui/material/SpeedDial';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import { CloudUploadOutlined, InsertChartOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useHistory } from 'react-router-dom';
import VisuallyHiddenInput from '../common/VisuallyHiddenInput';
import Drawer, { DrawerVariant } from '../common/drawer/Drawer';
import { useFormatter } from '../../../components/i18n';
import { commitMutation, handleError } from '../../../relay/environment';
import TextField from '../../../components/TextField';
import MarkdownField from '../../../components/MarkdownField';
import { resolveLink } from '../../../utils/Entity';

const useStyles = makeStyles((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1100,
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  speedDialButton: {
    backgroundColor: theme.palette.secondary.main,
    color: '#ffffff',
    '&:hover': {
      backgroundColor: theme.palette.secondary.main,
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
    configurationImport(file: $file)
  }
`;

const workspaceValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_workspaces',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

const WorkspaceCreation = ({ paginationOptions, type }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const inputRef = useRef();
  const [commitImportMutation] = useMutation(importMutation);
  const history = useHistory();

  const handleImport = (event) => {
    const importedFile = event.target.files[0];
    commitImportMutation({
      variables: { file: importedFile },
      onCompleted: (data) => {
        history.push(
          `${resolveLink('Dashboard')}/${data.configurationImport}`,
        );
      },
      onError: (error) => {
        handleError(error);
      },
    });
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    commitMutation({
      mutation: workspaceMutation,
      variables: {
        input: {
          ...values,
          type,
        },
      },
      updater: (store) => {
        const payload = store.getRootField('workspaceAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          paginationOptions,
          newEdge,
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  return (
      <>
        <VisuallyHiddenInput type="file" accept={'application/JSON'} ref={inputRef} onChange={handleImport} />
        <Drawer
          title={t('Create a workspace')}
          variant={type === 'dashboard' ? undefined : DrawerVariant.create}
          controlledDial={(type === 'dashboard') ? ({ onOpen }) => (
            <SpeedDial
              className={classes.createButton}
              ariaLabel="Create"
              icon={<SpeedDialIcon />}
              FabProps={{ color: 'secondary' }}
            >
              <SpeedDialAction
                title={t('Import dashboard')}
                icon={<CloudUploadOutlined />}
                tooltipTitle={t('Import dashboard')}
                onClick={() => inputRef.current?.click()}
                FabProps={{ classes: { root: classes.speedDialButton } }}
              />
              <SpeedDialAction
                title={t('Create a workspace')}
                icon={<InsertChartOutlined />}
                tooltipTitle={t('Create a workspace')}
                onClick={onOpen}
                FabProps={{ classes: { root: classes.speedDialButton } }}
              />
            </SpeedDial>
          ) : undefined}
        >
          {({ onClose }) => (
            <Formik
              initialValues={{
                name: '',
                description: '',
              }}
              validationSchema={workspaceValidation(t)}
              onSubmit={onSubmit}
              onReset={onClose}
            >
              {({ submitForm, handleReset, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <Field
                    component={MarkdownField}
                    name="description"
                    label={t('Description')}
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
                      {t('Cancel')}
                    </Button>
                    <Button
                      variant="contained"
                      color="secondary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Create')}
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
