import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Form, Formik, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import { compose, omit, pipe } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import Alert from '@mui/material/Alert';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';

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

const userMutation = graphql`
  mutation UserCreationMutation($input: UserAddInput!) {
    userAdd(input: $input) {
      ...UserLine_node
    }
  }
`;

const userValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  user_email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  firstname: Yup.string().nullable(),
  lastname: Yup.string().nullable(),
  description: Yup.string().nullable(),
  password: Yup.string().required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), null], t('The values do not match'))
    .required(t('This field is required')),
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

  onSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = pipe(omit(['confirmation']))(values);
    commitMutation({
      mutation: userMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('userAdd');
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
        this.handleClose();
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
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={this.state.open}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Create a user')}</Typography>
          </div>
          <div className={classes.container}>
            <Alert severity="info">
              {t('User will be created with default roles.')}
            </Alert>
            <br />
            <Formik
              initialValues={{
                name: '',
                user_email: '',
                firstname: '',
                lastname: '',
                description: '',
                password: '',
                confirmation: '',
              }}
              validationSchema={userValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onReset.bind(this)}
            >
              {({ submitForm, handleReset, isSubmitting }) => (
                <Form>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="user_email"
                    label={t('Email address')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="firstname"
                    label={t('Firstname')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="lastname"
                    label={t('Lastname')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={MarkDownField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows={4}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="password"
                    label={t('Password')}
                    type="password"
                    style={{ marginTop: 20 }}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="confirmation"
                    label={t('Confirmation')}
                    type="password"
                    fullWidth={true}
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
