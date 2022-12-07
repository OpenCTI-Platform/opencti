import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import { compose, assoc } from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../components/i18n';
import { commitMutation } from '../../../relay/environment';
import TextField from '../../../components/TextField';
import MarkDownField from '../../../components/MarkDownField';

const styles = (theme) => ({
  drawerPaper: {
    width: '50%',
    position: 'fixed',
    padding: '10px 35px 20px 35px',
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  dialogTitle: {
    padding: '16px 0 0 0',
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
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
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
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
        this.props.history.push('/dashboard/workspaces/dashboards');
        this.props.handleCreateDashboard();
        resetForm();
      },
    });
  }

  onReset() {
    this.props.handleCreateDashboard();
  }

  render() {
    const {
      t, classes, open,
    } = this.props;
    return (
      <>
        <Dialog
          open={open}
          classes={{ paper: classes.drawerPaper }}
        >
          <DialogTitle classes={{ root: classes.dialogTitle }}>
            {t('Create a Dashboard')}
            <Typography>
              {t('Add a custom dashboard to your organization')}
            </Typography>
          </DialogTitle>
          <Formik
            initialValues={{
              name: '',
              description: '',
            }}
            validationSchema={workspaceValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onReset.bind(this)}
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
                  component={MarkDownField}
                  name="description"
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 20 }}
                />
                <div className={classes.buttons}>
                  <Button
                    size='small'
                    variant="outlined"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Close')}
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    size='small'
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Add')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        </Dialog>
      </>
    );
  }
}

WorkspaceCreation.propTypes = {
  t: PropTypes.func,
  open: PropTypes.bool,
  type: PropTypes.string,
  theme: PropTypes.object,
  classes: PropTypes.object,
  history: PropTypes.object,
  paginationOptions: PropTypes.object,
  handleCreateDashboard: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(WorkspaceCreation);
