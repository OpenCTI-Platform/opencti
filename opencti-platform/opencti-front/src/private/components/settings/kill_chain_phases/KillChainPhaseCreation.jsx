import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { assoc, compose, pipe } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
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
  container: {
    padding: '10px 20px 20px 20px',
  },
});

const killChainPhaseMutation = graphql`
  mutation KillChainPhaseCreationMutation($input: KillChainPhaseAddInput!) {
    killChainPhaseAdd(input: $input) {
      ...KillChainPhasesLine_node
    }
  }
`;

const killChainPhaseValidation = (t) => Yup.object().shape({
  kill_chain_name: Yup.string().required(t('This field is required')),
  phase_name: Yup.string().required(t('This field is required')),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_killChainPhases',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class KillChainPhaseCreation extends Component {
  onSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = pipe(
      assoc('x_opencti_order', parseInt(values.x_opencti_order, 10)),
    )(values);
    commitMutation({
      mutation: killChainPhaseMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('killChainPhaseAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node');
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
        title={t('Create a kill chain phase')}
        variant={DrawerVariant.createWithPanel}
      >
        {({ onClose }) => (
          <Formik
            initialValues={{
              kill_chain_name: '',
              phase_name: '',
              x_opencti_order: '',
            }}
            validationSchema={killChainPhaseValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={onClose}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="kill_chain_name"
                  label={t('Kill chain name')}
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="phase_name"
                  label={t('Phase name')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="x_opencti_order"
                  label={t('Order')}
                  fullWidth={true}
                  type="number"
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

KillChainPhaseCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(KillChainPhaseCreation);
