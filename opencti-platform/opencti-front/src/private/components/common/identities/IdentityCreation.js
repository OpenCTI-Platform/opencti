import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { compose } from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import MenuItem from '@material-ui/core/MenuItem';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';

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

export const identityCreationIdentitiesSearchQuery = graphql`
  query IdentityCreationIdentitiesSearchQuery(
    $types: [String]
    $search: String
    $first: Int
  ) {
    identities(types: $types, search: $search, first: $first) {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
  }
`;

const identityMutation = graphql`
  mutation IdentityCreationMutation($input: IdentityAddInput!) {
    identityAdd(input: $input) {
      id
      name
      entity_type
    }
  }
`;

const identityValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  type: Yup.string().required(t('This field is required')),
});

class IdentityCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    commitMutation({
      mutation: identityMutation,
      variables: {
        input: values,
      },
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        if (this.props.contextual) {
          this.props.creationCallback(response);
          this.props.handleClose();
        } else {
          this.handleClose();
        }
      },
    });
  }

  onResetClassic() {
    this.handleClose();
  }

  onResetContextual() {
    this.props.handleClose();
  }

  renderClassic() {
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
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize="small" />
            </IconButton>
            <Typography variant="h6">{t('Create an entity')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '',
                description: '',
                type: '',
              }}
              validationSchema={identityValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onResetClassic.bind(this)}
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
                    component={TextField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={SelectField}
                    name="type"
                    label={t('Entity type')}
                    fullWidth={true}
                    inputProps={{
                      name: 'type',
                      id: 'type',
                    }}
                    containerstyle={{ marginTop: 20, width: '100%' }}
                  >
                    <MenuItem value="Sector">{t('Sector')}</MenuItem>
                    <MenuItem value="Organization">
                      {t('Organization')}
                    </MenuItem>
                    <MenuItem value="Region">{t('Region')}</MenuItem>
                    <MenuItem value="Country">{t('Country')}</MenuItem>
                    <MenuItem value="City">{t('City')}</MenuItem>
                    <MenuItem value="User">{t('Person')}</MenuItem>
                  </Field>
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
                      color="primary"
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

  renderContextual() {
    const {
      t, classes, inputValue, open, onlyAuthors,
    } = this.props;
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{
            name: inputValue,
            description: '',
            type: '',
          }}
          validationSchema={identityValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onResetContextual.bind(this)}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Dialog
                open={open}
                onClose={this.handleClose.bind(this)}
                fullWidth={true}
              >
                <DialogTitle>{t('Create an entity')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={TextField}
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={SelectField}
                    name="type"
                    label={t('Entity type')}
                    fullWidth={true}
                    containerstyle={{ marginTop: 20, width: '100%' }}
                  >
                    {!onlyAuthors ? (
                      <MenuItem value="Sector">{t('Sector')}</MenuItem>
                    ) : (
                      ''
                    )}
                    <MenuItem value="Organization">
                      {t('Organization')}
                    </MenuItem>
                    {!onlyAuthors ? (
                      <MenuItem value="Region">{t('Region')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {!onlyAuthors ? (
                      <MenuItem value="Country">{t('Country')}</MenuItem>
                    ) : (
                      ''
                    )}
                    {!onlyAuthors ? (
                      <MenuItem value="City">{t('City')}</MenuItem>
                    ) : (
                      ''
                    )}
                    <MenuItem value="User">{t('Person')}</MenuItem>
                  </Field>
                </DialogContent>
                <DialogActions>
                  <Button
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="primary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        </Formik>
      </div>
    );
  }

  render() {
    const { contextual } = this.props;
    if (contextual) {
      return this.renderContextual();
    }
    return this.renderClassic();
  }
}

IdentityCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  contextual: PropTypes.bool,
  onlyAuthors: PropTypes.bool,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  inputValue: PropTypes.string,
  creationCallback: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IdentityCreation);
