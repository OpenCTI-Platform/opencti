import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { compose } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import SimpleTextField from '../../../../components/SimpleTextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { insertNode } from '../../../../utils/store';

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
  dialog: {
    overflow: 'hidden',
  },
});

const labelMutation = graphql`
  mutation LabelCreationMutation($input: LabelAddInput!) {
    labelAdd(input: $input) {
      ...LabelsLine_node
    }
  }
`;

const labelContextualMutation = graphql`
  mutation LabelCreationContextualMutation($input: LabelAddInput!) {
    labelAdd(input: $input) {
      id
      value
    }
  }
`;

const labelValidation = (t) => Yup.object().shape({
  value: Yup.string().required(t('This field is required')),
  color: Yup.string().required(t('This field is required')),
});

class LabelCreation extends Component {
  onSubmit(values, { setSubmitting, resetForm }) {
    if (this.props.dryrun && this.props.contextual) {
      this.props.creationCallback({ labelAdd: values });
      return this.props.handleClose();
    }
    return commitMutation({
      mutation: this.props.contextual ? labelContextualMutation : labelMutation,
      variables: {
        input: values,
      },
      updater: (store) => {
        if (!this.props.contextual) {
          insertNode(
            store,
            'Pagination_labels',
            this.props.paginationOptions,
            'labelAdd',
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
        }
      },
    });
  }

  onResetContextual() {
    this.props.handleClose();
  }

  renderClassic() {
    const { t, classes } = this.props;
    return (
      <Drawer
        title={t('Create a label')}
        variant={DrawerVariant.createWithPanel}
      >
        {({ onClose }) => (
          <Formik
            initialValues={{
              value: '',
              color: '',
            }}
            validationSchema={labelValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={onClose}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={SimpleTextField}
                  variant="standard"
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

  renderContextual() {
    const { t, classes, open, inputValue, handleClose } = this.props;
    return (
      <>
        <Formik
          enableReinitialize={true}
          initialValues={{
            value: inputValue,
            color: '',
          }}
          validationSchema={labelValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onResetContextual.bind(this)}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Dialog
                open={open}
                PaperProps={{ elevation: 1 }}
                onClose={handleClose.bind(this)}
                fullWidth={true}
              >
                <DialogTitle>{t('Create a label')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialog }}>
                  <Field
                    component={SimpleTextField}
                    variant="standard"
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
      </>
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
