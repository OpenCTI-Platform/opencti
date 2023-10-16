import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { assoc, compose } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import Drawer, { DrawerVariant } from '../common/drawer/Drawer';
import inject18n from '../../../components/i18n';
import { commitMutation } from '../../../relay/environment';
import TextField from '../../../components/TextField';
import MarkdownField from '../../../components/MarkdownField';

const styles = (theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
});

const workspaceMutation = graphql`
  mutation WorkspaceCreationMutation($input: WorkspaceAddInput!) {
    workspaceAdd(input: $input) {
      ...WorkspaceLine_node
    }
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

class WorkspaceCreation extends Component {
  onSubmit(values, { setSubmitting, resetForm }) {
    commitMutation({
      mutation: workspaceMutation,
      variables: {
        input: assoc('type', this.props.type, values),
      },
      updater: (store) => {
        const payload = store.getRootField('workspaceAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          this.props.paginationOptions,
          newEdge,
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  }

  render() {
    const { t, classes } = this.props;
    return (
      <Drawer
        title={t('Create a workspace')}
        variant={DrawerVariant.create}
      >
        {({ onClose }) => (
          <Formik
            initialValues={{
              name: '',
              description: '',
            }}
            validationSchema={workspaceValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
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
    );
  }
}

WorkspaceCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  type: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(WorkspaceCreation);
