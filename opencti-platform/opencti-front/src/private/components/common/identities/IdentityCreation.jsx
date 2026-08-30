import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import DialogActions from '@mui/material/DialogActions';
import MenuItem from '@mui/material/MenuItem';
import withStyles from '@mui/styles/withStyles';
import { Field, Form, Formik } from 'formik';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import { v4 as uuid } from 'uuid';
import * as Yup from 'yup';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import SelectField from '../../../../components/fields/SelectField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { ExternalReferencesField } from '../form/ExternalReferencesField';
import ObjectLabelField from '../form/ObjectLabelField';
import ObjectMarkingField from '../form/ObjectMarkingField';

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

const IdentityCreation = (props) => {
  const { t_i18n } = useFormatter();
  const onSubmit = (values, { setSubmitting, resetForm }) => {
    if (props.dryrun && props.contextual) {
      props.creationCallback({
        identityAdd: {
          ...values,
          id: `identity--${uuid()}`,
        },
      });
      return props.handleClose();
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
        if (props.contextual) {
          props.creationCallback(response);
          props.handleClose();
        }
      },
    });
  };

  const onResetContextual = () => {
    props.handleClose();
  };

  const { inputValue, open, onlyAuthors, handleClose, dryrun } = props;
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
        validationSchema={identityValidation(t_i18n)}
        onSubmit={onSubmit}
        onReset={onResetContextual}
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
              open={open}
              onClose={handleClose}
              title={t_i18n('Create an entity')}
            >
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
                detectDuplicate={['Organization', 'Individual']}
              />
              <Field
                component={MarkdownField}
                name="description"
                label={t_i18n('Description')}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={{ marginTop: 20 }}
              />
              <Field
                component={SelectField}
                variant="standard"
                name="type"
                label={t_i18n('Entity type')}
                fullWidth={true}
                containerstyle={fieldSpacingContainerStyle}
              >
                {!onlyAuthors && (<MenuItem value="Sector">{t_i18n('Sector')}</MenuItem>)}
                <MenuItem value="Organization">{t_i18n('Organization')}</MenuItem>
                <MenuItem value="System">{t_i18n('System')}</MenuItem>
                <MenuItem value="Individual">{t_i18n('Individual')}</MenuItem>
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
              <DialogActions>
                <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {t_i18n('Create')}
                </Button>
              </DialogActions>
            </Dialog>
          </Form>
        )}
      </Formik>
    </>
  );
};

IdentityCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  contextual: PropTypes.bool,
  onlyAuthors: PropTypes.bool,
  open: PropTypes.bool,
  handleClose: PropTypes.func,
  inputValue: PropTypes.string,
  creationCallback: PropTypes.func,
};

export default withStyles(styles, { withTheme: true })(IdentityCreation);
