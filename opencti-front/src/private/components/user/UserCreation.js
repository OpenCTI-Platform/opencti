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
    overflow: 'hidden',
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

const userMutation = graphql`
    mutation UserCreationMutation($input: UserAddInput!) {
        userAdd(input: $input) {
            ...UserLine_user
        }
    }
`;

const userValidation = t => Yup.object().shape({
  username: Yup.string()
    .required(t('This field is required')),
  email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  firstname: Yup.string(),
  lastname: Yup.string(),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_users',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class UserCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, users: [] };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  onSubmit(values, { setSubmitting, resetForm, setErrors }) {
    commitMutation(environment, {
      mutation: userMutation,
      variables: {
        input: values,
      },
      updater: (store) => {
        const payload = store.getRootField('userAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(store, container.getDataID(), this.props.paginationOptions, newEdge);
      },
      /* optimisticUpdater: (store) => {
        const root = store.getRoot();
        const user = root.getLinkedRecord('me');
        const id = Math.floor(Math.random() * 999999) + 100000;
        const node = store.create(`client:newUser:V${id}`, 'User');
        node.setValue(`client:newUser:V${id}`, 'id');
        node.setValue('YOOOOOOOOOOOOOOOOOOOO', 'name');
        node.setValue(values.description, 'description');
        const newEdge = store.create(`client:newEdge:V${id}`, 'userEdge');
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
              {t('Create a user')}
            </Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                username: '', email: '', firstname: '', lastname: '',
              }}
              validationSchema={userValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onReset.bind(this)}
              render={({ submitForm, handleReset, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field name='username' component={TextField} label={t('Username')} fullWidth={true}/>
                  <Field name='email' component={TextField} label={t('Email address')} fullWidth={true} style={{ marginTop: 20 }}/>
                  <Field name='firstname' component={TextField} label={t('Firstname')} fullWidth={true} style={{ marginTop: 20 }}/>
                  <Field name='lastname' component={TextField} label={t('Lastname')} fullWidth={true} style={{ marginTop: 20 }}/>
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

UserCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(UserCreation);
