import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import IconButton from '@mui/material/IconButton';
import { TextFieldsOutlined } from '@mui/icons-material';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import Tooltip from '@mui/material/Tooltip';
import { Field, Form, Formik } from 'formik';
import DialogTitle from '@mui/material/DialogTitle';
import * as Yup from 'yup';
import Slide from '@mui/material/Slide';
import TextField from '../../../../components/TextField';
import inject18n from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { now } from '../../../../utils/Time';
import { isValidStixBundle } from '../../../../utils/String';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

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
    let file;
    if (isValidStixBundle(content)) {
      const blob = new Blob([content], { type: 'text/json' });
      file = new File(
        [blob],
        `${now()}_${this.props.entityId ? this.props.entityId : 'global'}.json`,
        {
          type: 'application/json',
        },
      );
    } else {
      const blob = new Blob([content], { type: 'text/plain' });
      file = new File(
        [blob],
        `${now()}_${this.props.entityId ? this.props.entityId : 'global'}.txt`,
        {
          type: 'text/plain',
        },
      );
    }
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
    const { t, color } = this.props;
    return (
      <React.Fragment>
        <Tooltip title={t('Copy/paste text content')}>
          <IconButton
            onClick={this.handleOpen.bind(this)}
            color={color || 'primary'}
            size="large"
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
                PaperProps={{ elevation: 1 }}
                open={this.state.open}
                onClose={this.handleClose.bind(this)}
                fullWidth={true}
                TransitionComponent={Transition}
              >
                <DialogTitle>{t('Free text import')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="content"
                    label={t('Content')}
                    fullWidth={true}
                    multiline={true}
                    rows="8"
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

export default R.compose(inject18n, withRouter)(FreeTextUploader);
