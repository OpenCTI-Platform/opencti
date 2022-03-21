import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import * as R from 'ramda';
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
import Fab from '@mui/material/Fab';
import { SimpleFileUpload } from 'formik-mui';
import { Add, Close } from '@mui/icons-material';
import {
  commitMutation,
  handleErrorInForm,
} from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import { insertNode } from '../../../../utils/Store';

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
  createButtonContextual: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 3000,
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

const externalReferenceCreationMutation = graphql`
  mutation ExternalReferenceCreationMutation(
    $input: ExternalReferenceAddInput!
  ) {
    externalReferenceAdd(input: $input) {
      id
      source_name
      description
      url
      external_id
      created
    }
  }
`;

const externalReferenceValidation = (t) => Yup.object().shape({
  source_name: Yup.string().required(t('This field is required')),
  external_id: Yup.string().nullable(),
  url: Yup.string().url(t('The value must be an URL')).nullable(),
  description: Yup.string().nullable(),
  file: Yup.object().nullable(),
});

class ExternalReferenceCreation extends Component {
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

  onSubmit(values, { setSubmitting, setErrors, resetForm }) {
    const finalValues = values.file.length === 0 ? R.dissoc('file', values) : values;
    commitMutation({
      mutation: externalReferenceCreationMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => insertNode(
        store,
        'Pagination_externalReferences',
        this.props.paginationOptions,
        'externalReferenceAdd',
      ),
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        if (this.props.onCreate) {
          this.props.onCreate(response.externalReferenceAdd, true);
        }
      },
    });
  }

  onSubmitContextual(values, { setSubmitting, setErrors, resetForm }) {
    const finalValues = values.file.length === 0 ? R.dissoc('file', values) : values;
    commitMutation({
      mutation: externalReferenceCreationMutation,
      variables: {
        input: finalValues,
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        this.props.creationCallback(response);
        this.props.handleClose();
      },
    });
  }

  onResetClassic() {
    this.handleClose();
  }

  onResetContextual() {
    if (this.props.handleClose) {
      this.props.handleClose();
    } else {
      this.handleClose();
    }
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
            <Typography variant="h6">
              {t('Create an external reference')}
            </Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                source_name: '',
                external_id: '',
                url: '',
                description: '',
                file: '',
              }}
              validationSchema={externalReferenceValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onResetClassic.bind(this)}
            >
              {({ submitForm, handleReset, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="source_name"
                    label={t('Source name')}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="external_id"
                    label={t('External ID')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="url"
                    label={t('URL')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
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
                    component={SimpleFileUpload}
                    name="file"
                    label={t('Associated file')}
                    FormControlProps={{ style: { marginTop: 20 } }}
                    InputLabelProps={{ fullWidth: true, variant: 'standard' }}
                    InputProps={{
                      fullWidth: true,
                      variant: 'standard',
                    }}
                    fullWidth={true}
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
    const { t, classes, inputValue, display, open, handleClose } = this.props;
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        {!handleClose && (
          <Fab
            onClick={this.handleOpen.bind(this)}
            color="secondary"
            aria-label="Add"
            className={classes.createButtonContextual}
          >
            <Add />
          </Fab>
        )}
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={!handleClose ? this.state.open : open}
          onClose={
            !handleClose ? this.handleClose.bind(this) : handleClose.bind(this)
          }
        >
          <Formik
            enableReinitialize={true}
            initialValues={{
              source_name: inputValue,
              external_id: '',
              url: '',
              description: '',
              file: '',
            }}
            validationSchema={externalReferenceValidation(t)}
            onSubmit={
              !handleClose
                ? this.onSubmit.bind(this)
                : this.onSubmitContextual.bind(this)
            }
            onReset={this.onResetContextual.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <DialogTitle>{t('Create an external reference')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="source_name"
                    label={t('Source name')}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="external_id"
                    label={t('External ID')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="url"
                    label={t('URL')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={MarkDownField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20, marginBottom: 20 }}
                  />
                  <Field
                    component={SimpleFileUpload}
                    name="file"
                    label={t('Associated file')}
                    FormControlProps={{
                      style: { marginTop: 20, width: '100%' },
                    }}
                    InputLabelProps={{ fullWidth: true, variant: 'standard' }}
                    InputProps={{
                      fullWidth: true,
                      variant: 'standard',
                    }}
                    fullWidth={true}
                  />
                </DialogContent>
                <DialogActions>
                  <Button
                    onClick={handleClose || handleReset}
                    disabled={isSubmitting}
                  >
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
              </Form>
            )}
          </Formik>
        </Dialog>
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

ExternalReferenceCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  contextual: PropTypes.bool,
  display: PropTypes.bool,
  inputValue: PropTypes.string,
  onCreate: PropTypes.func,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  creationCallback: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ExternalReferenceCreation);
