import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import { compose } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import MenuItem from '@mui/material/MenuItem';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import MarkdownField from '../../../../components/MarkdownField';
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

export const locationCreationLocationsSearchQuery = graphql`
  query LocationCreationLocationsSearchQuery(
    $types: [String]
    $search: String
    $first: Int
  ) {
    locations(types: $types, search: $search, first: $first) {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
  }
`;

const locationMutation = graphql`
  mutation LocationCreationMutation($input: LocationAddInput!) {
    locationAdd(input: $input) {
      id
      standard_id
      name
      entity_type
    }
  }
`;

const locationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  type: Yup.string().required(t('This field is required')),
});

class LocationCreation extends Component {
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
    commitMutation({
      mutation: locationMutation,
      variables: {
        input: values,
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
    if (this.props.handleClose) {
      this.props.handleClose();
    }
  }

  render() {
    const { t, inputValue, open, onlyAuthors } = this.props;
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{
            name: inputValue,
            description: '',
            type: '',
          }}
          validationSchema={locationValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onResetContextual.bind(this)}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Dialog
                PaperProps={{ elevation: 1 }}
                open={open}
                onClose={this.handleClose.bind(this)}
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
                    {!onlyAuthors && (
                      <MenuItem value="Sector">{t('Sector')}</MenuItem>
                    )}
                    <MenuItem value="Organization">
                      {t('Organization')}
                    </MenuItem>
                    {!onlyAuthors && (
                      <MenuItem value="Region">{t('Region')}</MenuItem>
                    )}
                    {!onlyAuthors && (
                      <MenuItem value="Country">{t('Country')}</MenuItem>
                    )}
                    {!onlyAuthors && (
                      <MenuItem value="City">{t('City')}</MenuItem>
                    )}
                    <MenuItem value="Individual">{t('Individual')}</MenuItem>
                  </Field>
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
      </div>
    );
  }
}

LocationCreation.propTypes = {
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
)(LocationCreation);
