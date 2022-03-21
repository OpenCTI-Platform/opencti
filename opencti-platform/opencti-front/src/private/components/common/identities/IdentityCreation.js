import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { compose } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import MenuItem from '@mui/material/MenuItem';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import MarkDownField from '../../../../components/MarkDownField';
import ObjectLabelField from '../form/ObjectLabelField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import ExternalReferencesField from '../form/ExternalReferencesField';

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
    const finalValues = R.pipe(
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('objectLabel', R.pluck('value', values.objectLabel)),
      R.assoc('externalReferences', R.pluck('value', values.externalReferences)),
    )(values);
    commitMutation({
      mutation: identityMutation,
      variables: {
        input: finalValues,
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
            <Typography variant="h6">{t('Create an entity')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '',
                description: '',
                type: '',
                objectMarking: [],
                objectLabel: [],
                externalReferences: [],
              }}
              validationSchema={identityValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onResetClassic.bind(this)}
            >
              {({
                submitForm,
                handleReset,
                isSubmitting,
                setFieldValue,
                values,
              }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                    detectDuplicate={['Organization', 'Individual']}
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
                  <Field
                    component={SelectField}
                    variant="standard"
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
                    <MenuItem value="Individual">{t('Individual')}</MenuItem>
                    <MenuItem value="System">{t('System')}</MenuItem>
                  </Field>
                  <ObjectLabelField
                    name="objectLabel"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    values={values.objectLabel}
                  />
                  <ObjectMarkingField
                    name="objectMarking"
                    style={{ marginTop: 20, width: '100%' }}
                  />
                  <ExternalReferencesField
                    name="externalReferences"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    values={values.externalReferences}
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

  renderContextual() {
    const { t, inputValue, open, onlyAuthors, handleClose } = this.props;
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{
            name: inputValue,
            description: '',
            type: '',
            objectMarking: [],
            objectLabel: [],
            externalReferences: [],
          }}
          validationSchema={identityValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onResetContextual.bind(this)}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
            setFieldValue,
            values,
          }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Dialog
                PaperProps={{ elevation: 1 }}
                open={open}
                onClose={handleClose.bind(this)}
                fullWidth={true}
              >
                <DialogTitle>{t('Create an entity')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                    detectDuplicate={['Organization', 'Individual']}
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
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="type"
                    label={t('Entity type')}
                    fullWidth={true}
                    containerstyle={{ marginTop: 20, width: '100%' }}
                  >
                    {!onlyAuthors && (
                      <MenuItem value="Sector">{t('Sector')}</MenuItem>
                    )}
                    <MenuItem value="Organization">
                      {t('Organization')}
                    </MenuItem>
                    {!onlyAuthors && (
                      <MenuItem value="Region">{t('Region')}</MenuItem>
                    )}
                    {!onlyAuthors && (
                      <MenuItem value="Country">{t('Country')}</MenuItem>
                    )}
                    {!onlyAuthors && (
                      <MenuItem value="City">{t('City')}</MenuItem>
                    )}
                    <MenuItem value="Individual">{t('Individual')}</MenuItem>
                  </Field>
                  <ObjectLabelField
                    name="objectLabel"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    values={values.objectLabel}
                  />
                  <ObjectMarkingField
                    name="objectMarking"
                    style={{ marginTop: 20, width: '100%' }}
                  />
                  <ExternalReferencesField
                    name="externalReferences"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    values={values.externalReferences}
                  />
                </DialogContent>
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
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
