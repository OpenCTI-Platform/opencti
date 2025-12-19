import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import { compose } from 'ramda';
import * as Yup from 'yup';
import { v4 as uuid } from 'uuid';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import MenuItem from '@mui/material/MenuItem';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import ObjectLabelField from '../form/ObjectLabelField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import { ExternalReferencesField } from '../form/ExternalReferencesField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

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
      standard_id
      name
      entity_type
    }
  }
`;

const identityValidation = (t) => Yup.object().shape({
  name: Yup.string().trim().required(t('This field is required')),
  type: Yup.string().trim().required(t('This field is required')),
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
    if (this.props.dryrun && this.props.contextual) {
      this.props.creationCallback({
        identityAdd: {
          ...values,
          id: `identity--${uuid()}`,
        },
      });
      return this.props.handleClose();
    }
    const finalValues = R.pipe(
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('objectLabel', R.pluck('value', values.objectLabel)),
      R.assoc('externalReferences', R.pluck('value', values.externalReferences)),
    )(values);
    return commitMutation({
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

  onResetContextual() {
    this.props.handleClose();
  }

  render() {
    const { t, inputValue, open, onlyAuthors, handleClose, dryrun } = this.props;
    return (
      <>
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
            <Form>
              <Dialog
                slotProps={{ paper: { elevation: 1 } }}
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
                    component={MarkdownField}
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
                    containerstyle={fieldSpacingContainerStyle}
                  >
                    {!onlyAuthors && (<MenuItem value="Sector">{t('Sector')}</MenuItem>)}
                    <MenuItem value="Organization">{t('Organization')}</MenuItem>
                    <MenuItem value="System">{t('System')}</MenuItem>
                    <MenuItem value="Individual">{t('Individual')}</MenuItem>
                  </Field>
                  {!dryrun && (
                    <ObjectLabelField
                      name="objectLabel"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.objectLabel}
                    />
                  )}
                  {!dryrun && (
                    <ObjectMarkingField
                      name="objectMarking"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                    />
                  )}
                  {!dryrun && (
                    <ExternalReferencesField
                      name="externalReferences"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.externalReferences}
                    />
                  )}
                </DialogContent>
                <DialogActions>
                  <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
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
