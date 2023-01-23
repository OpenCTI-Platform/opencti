/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import * as Yup from 'yup';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import { Formik, Form, Field } from 'formik';
import Button from '@material-ui/core/Button';
import DialogTitle from '@material-ui/core/DialogTitle';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import inject18n from '../../../../../components/i18n';
import { commitMutation } from '../../../../../relay/environment';
import { adaptFieldValue } from '../../../../../utils/String';
import TextField from '../../../../../components/TextField';
import MarkDownField from '../../../../../components/MarkDownField';
import { toastGenericError } from "../../../../../utils/bakedToast";


const styles = (theme) => ({
  dialogMain: {
    overflow: 'hidden',
  },
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogContent: {
    padding: '0 24px',
    marginBottom: '24px',
    overflow: 'hidden',
  },
  dialogClosebutton: {
    float: 'left',
    marginLeft: '15px',
    marginBottom: '20px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
});

const externalReferencesEntityEditionContainerMutation = graphql`
  mutation ExternalReferenceEntityEditionContainerMutation(
    $id: ID!,
    $input: [EditInput]!
  ) {
    editCyioExternalReference(id: $id, input: $input) {
      id
    }
  }
`;

const ExternalReferenceValidation = (t) => Yup.object().shape({
  source_name: Yup.string().required(t('This field is required')),
  url: Yup.string().url(t('The value must be a valid URL (scheme://host:port/path). For example, https://cyio.darklight.ai')),
});

class ExternalReferenceEntityEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      details: false,
      close: false,
      onSubmit: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
    event.stopPropagation();
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleSubmit() {
    this.setState({ onSumbit: true });
  }

  onReset() {
    this.props.handleDisplayEdit();
  }

  handleCancelCloseClick() {
    this.setState({ close: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const result = R.reject(R.equals(''))(values);
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => ({
        'key': n[0],
        'value': adaptFieldValue(n[1]),
      })),
    )(result);
    commitMutation({
      mutation: externalReferencesEntityEditionContainerMutation,
      variables: {
        id: this.props.externalReference.id,
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (data) => {
        setSubmitting(false);
        resetForm();
        this.props.history.push('/data/entities/external_references');
      },
      onError: (err) => {
        console.error(err);
        toastGenericError('Request Failed');
      }
    });
    this.setState({ onSubmit: true });
  }

  render() {
    const {
      classes,
      t,
      disabled,
      externalReference,
    } = this.props;
    const initialValues = R.pipe(
      R.assoc('url', externalReference?.url || ''),
      R.assoc('description', externalReference?.description || ''),
      R.assoc('source_name', externalReference?.source_name || ''),
      R.assoc('external_id', externalReference?.external_id || ''),
      R.pick([
        'url',
        'description',
        'source_name',
        'external_id',
      ]),
    )(externalReference);
    return (
      <>
        <Dialog
          open={this.props.displayEdit}
          keepMounted={true}
          className={classes.dialogMain}
        >
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={ExternalReferenceValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onReset.bind(this)}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form>
                <DialogTitle classes={{ root: classes.dialogTitle }}>{t('External Reference')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Field
                    component={TextField}
                    name="source_name"
                    label={t('Source name')}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    name="external_id"
                    label={t('External ID')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
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
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogClosebutton }}>
                  <Button
                    size='small'
                    variant="outlined"
                    onClick={handleReset}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    size='small'
                    color="primary"
                    variant="contained"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Submit')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
        </Dialog>
      </>
    );
  }
}

ExternalReferenceEntityEditionContainer.propTypes = {
  handleDisplayEdit: PropTypes.func,
  displayEdit: PropTypes.bool,
  history: PropTypes.object,
  disabled: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  connectionKey: PropTypes.string,
  externalReference: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(ExternalReferenceEntityEditionContainer);
