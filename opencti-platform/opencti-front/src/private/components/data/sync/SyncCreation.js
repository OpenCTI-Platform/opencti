import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/SwitchField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
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
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
    padding: '20px 0px 20px 60px',
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
  container: {
    padding: '10px 20px 20px 20px',
  },
  title: {
    float: 'left',
  },
});

const syncCreationMutation = graphql`
  mutation SyncCreationMutation($input: SynchronizerAddInput!) {
    synchronizerAdd(input: $input) {
      ...SyncLine_node
    }
  }
`;

export const syncCheckMutation = graphql`
  mutation SyncCreationCheckMutation($input: SynchronizerAddInput!) {
    synchronizerTest(input: $input)
  }
`;

const syncCreationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  uri: Yup.string().required(t('This field is required')),
  token: Yup.string().required(t('This field is required')),
  stream_id: Yup.string().required(t('This field is required')),
  listen_deletion: Yup.bool(),
  ssl_verify: Yup.bool(),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_synchronizers',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

const SyncCreation = (props) => {
  const { t, classes } = props;
  const [open, setOpen] = useState(false);
  const [verified, setVerified] = useState(false);

  const handleOpen = () => {
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
  };
  const handleVerify = (values) => {
    commitMutation({
      mutation: syncCheckMutation,
      variables: {
        input: values,
      },
      onCompleted: (data) => {
        if (data && data.synchronizerTest === 'Connection success') {
          MESSAGING$.notifySuccess(t('Connection successfully verified'));
          setVerified(true);
        }
      },
      onError: () => {
        setVerified(false);
      },
    });
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    commitMutation({
      mutation: syncCreationMutation,
      variables: {
        input: values,
      },
      updater: (store) => {
        const payload = store.getRootField('synchronizerAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node');
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          props.paginationOptions,
          newEdge,
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };

  const onReset = () => {
    handleClose();
  };

  return (
    <div>
      <Fab
        onClick={handleOpen}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}
      >
        <Add />
      </Fab>
      <Drawer
        open={open}
        anchor="right"
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
          >
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6">{t('Create a synchronizer')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik
            initialValues={{
              name: '',
              uri: '',
              token: '',
              stream_id: 'live',
              listen_deletion: false,
              ssl_verify: false,
            }}
            validationSchema={syncCreationValidation(t)}
            onSubmit={onSubmit}
            onReset={onReset}
          >
            {({
              submitForm, handleReset, isSubmitting, values,
            }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  name="name"
                  label={t('Name')}
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  name="uri"
                  label={t('Remote OpenCTI URL')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  name="token"
                  label={t('Remote OpenCTI token')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  name="stream_id"
                  label={t('Remote OpenCTI stream ID')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="ssl_verify"
                  label={t('Verify SSL certificate')}
                  containerstyle={{ marginTop: 20 }}
                />
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="listen_deletion"
                  label={t('Take deletions into account')}
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
                    onClick={() => handleVerify(values)}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Verify')}
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={submitForm}
                    disabled={!verified || isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Create')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        </div>
      </Drawer>
    </div>
  );
};

SyncCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(SyncCreation);
