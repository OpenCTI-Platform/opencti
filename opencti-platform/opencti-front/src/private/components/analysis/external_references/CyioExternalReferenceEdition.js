import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
// import { createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import { compose, pick } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import * as Yup from 'yup';
import { commitMutation as CM } from 'react-relay';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
import {
  commitMutation,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import { toastGenericError } from '../../../../utils/bakedToast';

const styles = (theme) => ({
  header: {
    // backgroundColor: theme.palette.navAlt.backgroundHeader,
    // color: theme.palette.navAlt.backgroundHeaderText,
    padding: '15px 0 0 20px',
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
    padding: '0 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.header.text,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
});

// const subscription = graphql`
//   subscription CyioExternalReferenceEditionSubscription($id: ID!) {
//     externalReference(id: $id) {
//       id
//       # ...CyioExternalReferenceEdition_externalReference
//     }
//   }
// `;

const cyioExternalReferenceMutationFieldPatch = graphql`
  mutation CyioExternalReferenceEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    editCyioExternalReference(
      id: $id,
      input: $input
      ) {
        id
        # ...CyioExternalReferenceEdition_externalReference
    }
  }
`;

const cyioExternalReferenceEditionFocus = graphql`
  mutation CyioExternalReferenceEditionFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    externalReferenceEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const cyioExternalReferenceValidation = (t) => Yup.object().shape({
  source_name: Yup.string().required(t('This field is required')),
  external_id: Yup.string(),
  url: Yup.string().url(t('The value must be a valid URL (scheme://host:port/path). For example, https://cyio.darklight.ai')),
  description: Yup.string(),
});

class CyioExternalReferenceEditionContainer extends Component {
  // constructor(props) {
  // super(props);
  // this.sub = requestSubscription({
  //   subscription,
  //   variables: { id: props.externalReference.id },
  // });
  // }

  // componentWillUnmount() {
  //   this.sub.dispose();
  // }

  handleChangeFocus(name) {
    commitMutation({
      mutation: cyioExternalReferenceEditionFocus,
      variables: {
        id: this.props.externalReference.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    CM(environmentDarkLight, {
      mutation: cyioExternalReferenceMutationFieldPatch,
      variables: {
        id: this.props.externalReference.id,
        input: [
          { key: 'source_name', value: values.source_name },
          { key: 'external_id', value: values.external_id },
          { key: 'url', value: values.url },
          { key: 'description', value: values.description },
        ],
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.props.handleClose();
        this.props.refreshQuery();
      },
      onError: () => {
        toastGenericError('Failed to update external reference');
      },
    });
  }

  // handleSubmitField(name, value) {
  //   cyioExternalReferenceValidation(this.props.t)
  //     .validateAt(name, { [name]: value })
  //     .then(() => {
  //       commitMutation({
  //         mutation: cyioExternalReferenceMutationFieldPatch,
  //         variables: {
  //           id: this.props.externalReference.id,
  //           input: { key: name, value: value || '' },
  //         },
  //       });
  //     })
  //     .catch(() => false);
  // }

  onReset() {
    this.props.handleClose();
  }

  render() {
    const {
      t, classes, externalReference,
    } = this.props;
    // const { editContext } = externalReference;
    const initialValues = pick(
      ['source_name', 'external_id', 'url', 'description'],
      externalReference,
    );
    return (
      <div>
        <div className={classes.header}>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('External Reference')}
          </Typography>
          {/* <SubscriptionAvatars context={editContext} /> */}
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Formik
            // enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={cyioExternalReferenceValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onReset.bind(this)}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
            }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
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
                  // label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows={4}
                  style={{ marginTop: 20 }}
                />
                <div style={{
                  float: 'left',
                  margin: '20px 0 30px 0',
                }}>
                  <Button
                    variant="outlined"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    style={{ marginRight: '15px' }}
                    size="small"
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    size="small"
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Update')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        </div>
      </div>
    );
  }
}

CyioExternalReferenceEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  externalReference: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CyioExternalReferenceEditionContainer);
