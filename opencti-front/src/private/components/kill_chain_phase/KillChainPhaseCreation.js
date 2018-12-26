import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { commitMutation } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import { compose, head } from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../components/i18n';
import environment from '../../../relay/environment';
import TextField from '../../../components/TextField';

const styles = theme => ({
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
    marginLeft: theme.spacing.unit * 2,
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
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
            ...KillChainPhaseLine_killChainPhase
        }
    }
`;

const killChainPhaseValidation = t => Yup.object().shape({
  kill_chain_name: Yup.string()
    .required(t('This field is required')),
  phase_name: Yup.string()
    .required(t('This field is required')),
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
  constructor(props) {
    super(props);
    this.state = { open: false, killChainPhases: [] };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  onSubmit(values, { setSubmitting, resetForm, setErrors }) {
    values.phase_order = parseInt(values.phase_order, 10);
    commitMutation(environment, {
      mutation: killChainPhaseMutation,
      variables: {
        input: values,
      },
      updater: (store) => {
        const payload = store.getRootField('killChainPhaseAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(store, container.getDataID(), this.props.paginationOptions, newEdge);
      },
      /* optimisticUpdater: (store) => {
        const root = store.getRoot();
        const user = root.getLinkedRecord('me');
        const id = Math.floor(Math.random() * 999999) + 100000;
        const node = store.create(`client:newKillChainPhase:V${id}`, 'KillChainPhase');
        node.setValue(`client:newKillChainPhase:V${id}`, 'id');
        node.setValue('YOOOOOOOOOOOOOOOOOOOO', 'name');
        node.setValue(values.description, 'description');
        const newEdge = store.create(`client:newEdge:V${id}`, 'killChainPhaseEdge');
        newEdge.setLinkedRecord(node, 'node');
        sharedUpdater(store, user.getDataID(), this.props.orderBy, newEdge);
      }, */
      onCompleted: (response, errors) => {
        setSubmitting(false);
        if (errors) {
          const error = this.props.t(head(errors).message);
          setErrors({ name: error }); // Push the error in the name field
        } else {
          resetForm();
          this.handleClose();
        }
      },
    });
  }

  onReset() {
    this.handleClose();
  }

  render() {
    const { t, classes } = this.props;
    return (
      <div>
        <Fab onClick={this.handleOpen.bind(this)}
             color='secondary' aria-label='Add'
             className={classes.createButton}><Add/></Fab>
        <Drawer open={this.state.open} anchor='right' classes={{ paper: classes.drawerPaper }} onClose={this.handleClose.bind(this)}>
          <div className={classes.header}>
            <IconButton aria-label='Close' className={classes.closeButton} onClick={this.handleClose.bind(this)}>
              <Close fontSize='small'/>
            </IconButton>
            <Typography variant='h6'>
              {t('Create a kill chain phase')}
            </Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                kill_chain_name: '', phase_name: '', phase_order: '',
              }}
              validationSchema={killChainPhaseValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onReset.bind(this)}
              render={({ submitForm, handleReset, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field name='kill_chain_name' component={TextField} label={t('Kill chain name')} fullWidth={true}/>
                  <Field name='phase_name' component={TextField} label={t('Phase name')} fullWidth={true} style={{ marginTop: 20 }}/>
                  <Field name='phase_order' component={TextField} label={t('Order')} fullWidth={true} type='number' style={{ marginTop: 20 }}/>
                  <div className={classes.buttons}>
                    <Button variant="contained" onClick={handleReset} disabled={isSubmitting} classes={{ root: classes.button }}>
                      {t('Cancel')}
                    </Button>
                    <Button variant='contained' color='primary' onClick={submitForm} disabled={isSubmitting} classes={{ root: classes.button }}>
                      {t('Create')}
                    </Button>
                  </div>
                </Form>
              )}
            />
          </div>
        </Drawer>
      </div>
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
