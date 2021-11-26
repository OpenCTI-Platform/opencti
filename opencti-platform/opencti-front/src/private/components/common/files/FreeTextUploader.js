import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import IconButton from '@material-ui/core/IconButton';
import { TextFieldsOutlined } from '@material-ui/icons';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Dialog from '@material-ui/core/Dialog';
import Tooltip from '@material-ui/core/Tooltip';
import { Field, Form, Formik } from 'formik';
import DialogTitle from '@material-ui/core/DialogTitle';
import * as Yup from 'yup';
import { withStyles } from '@material-ui/core/styles';
import Slide from '@material-ui/core/Slide';
import TextField from '../../../../components/TextField';
import inject18n from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { now } from '../../../../utils/Time';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
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

const freeTextUploaderGlobalMutation = graphql`
  mutation FreeTextUploaderGlobalMutation($file: Upload!) {
    uploadImport(file: $file) {
      ...FileLine_file
    }
  }
`;

const freeTextUploaderEntityMutation = graphql`
  mutation FreeTextUploaderEntityMutation($id: ID!, $file: Upload!) {
    stixCoreObjectEdit(id: $id) {
      importPush(file: $file) {
        ...FileLine_file
      }
    }
  }
`;

const freeTextValidation = (t) => Yup.object().shape({
  content: Yup.string().required(t('This field is required')),
});

class FreeTextUploader extends Component {
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
    const { entityId, onUploadSuccess } = this.props;
    const { content } = values;
    const blob = new Blob([content], { type: 'text/plain' });
    const file = new File(
      [blob],
      `${now()}_${this.props.entityId ? this.props.entityId : 'global'}.txt`,
      {
        type: 'text/plain',
      },
    );
    commitMutation({
      mutation: entityId
        ? freeTextUploaderEntityMutation
        : freeTextUploaderGlobalMutation,
      variables: {
        file,
        id: entityId,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        MESSAGING$.notifySuccess('File successfully uploaded');
        onUploadSuccess();
      },
    });
  }

  render() {
    const { t, classes, color } = this.props;
    return (
      <React.Fragment>
        <Tooltip title={t('Copy/paste text content')}>
          <IconButton
            onClick={this.handleOpen.bind(this)}
            color={color || 'primary'}
          >
            <TextFieldsOutlined />
          </IconButton>
        </Tooltip>
        <Formik
          enableReinitialize={true}
          initialValues={{ content: '' }}
          validationSchema={freeTextValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.handleClose.bind(this)}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Dialog
                open={this.state.open}
                onClose={this.handleClose.bind(this)}
                fullWidth={true}
                TransitionComponent={Transition}
              >
                <DialogTitle>{t('Free text import')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={TextField}
                    name="content"
                    label={t('Content')}
                    fullWidth={true}
                    multiline={true}
                    rows="8"
                  />
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
                    {t('Import')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        </Formik>
      </React.Fragment>
    );
  }
}

FreeTextUploader.propTypes = {
  entityId: PropTypes.string,
  onUploadSuccess: PropTypes.func.isRequired,
  color: PropTypes.string,
};

export default R.compose(
  inject18n,
  withRouter,
  withStyles(styles, { withTheme: true }),
)(FreeTextUploader);
