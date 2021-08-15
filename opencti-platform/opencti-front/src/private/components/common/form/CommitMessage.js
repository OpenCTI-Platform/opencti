import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { compose } from 'ramda';
import * as Yup from 'yup';
import { withStyles } from '@material-ui/core/styles';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import inject18n from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import { commitMutation } from '../../../../relay/environment';

const styles = () => ({
  container: {
    padding: '10px 20px 20px 20px',
  },
});

const commitMessageValidation = () => Yup.object().shape({
  message: Yup.string(),
});

class CommitMessage extends Component {
  onSubmit(values) {
    const { mutation, variables, handleClose } = this.props;
    const finalVariables = variables;
    if (values.message && values.message.length > 0) {
      if (variables.input) {
        finalVariables.input.commitMessage = values.message;
      } else {
        finalVariables.commitMessage = values.message;
      }
    }
    commitMutation({
      mutation,
      variables: finalVariables,
    });
    handleClose();
  }

  render() {
    const { open, handleClose, t } = this.props;
    return (
      <Formik
        enableReinitialize={true}
        initialValues={{ message: '' }}
        validationSchema={commitMessageValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
        onReset={this.onSubmit.bind(this)}
      >
        {({ submitForm, handleReset, isSubmitting }) => (
          <Form>
            <Dialog
              open={open}
              onClose={handleClose.bind(this)}
              fullWidth={true}
            >
              <DialogTitle>{t('Commit message')}</DialogTitle>
              <DialogContent>
                <Field
                  component={MarkDownField}
                  name="message"
                  label={t('Message')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                />
              </DialogContent>
              <DialogActions>
                <Button onClick={handleReset} disabled={isSubmitting}>
                  {t('Cancel')}
                </Button>
                <Button
                  color="primary"
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
    );
  }
}

CommitMessage.propTypes = {
  mutation: PropTypes.func,
  variables: PropTypes.object,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CommitMessage);
