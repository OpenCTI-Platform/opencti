import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import { compose } from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
// import { commitMutation as CM } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
// import environmentDarkLight from '../../../../relay/environmentDarkLight';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';

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
  container: {
    padding: '10px 20px 20px 20px',
  },
  dialog: {
    overflow: 'hidden',
  },
});

const labelMutation = graphql`
  mutation LabelCreationMutation($input: LabelAddInput!) {
    labelAdd(input: $input) {
      ...LabelLine_node
    }
  }
`;

export const labelContextualMutation = graphql`
  mutation LabelCreationContextualMutation($input: CyioLabelAddInput!) {
    createCyioLabel(input: $input) {
      id
      name
      color
    }
  }
`;

const labelValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  color: Yup.string().required(t('This field is required')),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_labels',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class LabelCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, labels: [] };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    // CM(environmentDarkLight, {
    //   mutation: labelContextualMutation,
    //   variables: {
    //     input: values,
    //   },
    //   setSubmitting,
    //   onCompleted: (response) => {
    //     setSubmitting(false);
    //     resetForm();
    //     if (this.props.contextual) {
    //       this.props.creationCallback(response);
    //       this.props.handleClose();
    //     } else {
    //       this.handleClose();
    //     }
    //   },
    //   onError: (err) => console.log('LabelCreationMutationError', err),
    // });
    commitMutation({
      mutation: this.props.contextual ? labelContextualMutation : labelMutation,
      variables: {
        input: values,
      },
      updater: (store) => {
        if (!this.props.contextual) {
          const payload = store.getRootField('labelAdd');
          const newEdge = payload.setLinkedRecord(payload, 'node');
          const container = store.getRoot();
          sharedUpdater(
            store,
            container.getDataID(),
            this.props.paginationOptions,
            newEdge,
          );
        }
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
            <Typography variant="h6">{t('Create a label')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                value: '',
                color: '',
              }}
              validationSchema={labelValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onResetClassic.bind(this)}
            >
              {({ submitForm, handleReset, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    name="value"
                    label={t('Value')}
                    fullWidth={true}
                  />
                  <Field
                    component={ColorPickerField}
                    name="color"
                    label={t('Color')}
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
      t, classes, open, inputValue, handleClose,
    } = this.props;
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{
            name: inputValue,
            color: '',
            description: '',
          }}
          validationSchema={labelValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onResetContextual.bind(this)}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Dialog
                open={open}
                onClose={handleClose.bind(this)}
                fullWidth={true}
              >
                <DialogTitle>{t('Create a label')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialog }}>
                  <Field
                    component={TextField}
                    name="name"
                    label={t('Label')}
                    fullWidth={true}
                    style={{ marginBottom: 10 }}
                  />
                  <Field
                    component={TextField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                  />
                  <Field
                    component={ColorPickerField}
                    name="color"
                    label={t('Color')}
                    fullWidth={true}
                    style={{ marginTop: 10 }}
                  />
                </DialogContent>
                <DialogActions style={{ margin: '0 25px 10px 0' }}>
                  <Button
                    variant="outlined"
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
                    {t('Add')}
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

LabelCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  contextual: PropTypes.bool,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  inputValue: PropTypes.string,
  creationCallback: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(LabelCreation);
