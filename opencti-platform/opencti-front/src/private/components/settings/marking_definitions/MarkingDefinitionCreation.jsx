import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { assoc, compose, pipe } from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
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
});

const markingDefinitionMutation = graphql`
  mutation MarkingDefinitionCreationMutation(
    $input: MarkingDefinitionAddInput!
  ) {
    markingDefinitionAdd(input: $input) {
      ...MarkingDefinitionLine_node
    }
  }
`;

const markingDefinitionValidation = (t) => Yup.object().shape({
  definition_type: Yup.string().required(t('This field is required')),
  definition: Yup.string().required(t('This field is required')),
  x_opencti_color: Yup.string().required(t('This field is required')),
  x_opencti_order: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
});

class MarkingDefinitionCreation extends Component {
  onSubmit(values, { setSubmitting, resetForm }) {
    const finalValues = pipe(
      assoc('x_opencti_order', parseInt(values.x_opencti_order, 10)),
    )(values);
    commitMutation({
      mutation: markingDefinitionMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        insertNode(store, 'Pagination_markingDefinitions', this.props.paginationOptions, 'markingDefinitionAdd');
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  }

  render() {
    const { t, classes } = this.props;
    return (
      <Drawer
        title={t('Create a marking definition')}
        variant={DrawerVariant.createWithPanel}
      >
        {({ onClose }) => (
          <Formik
            initialValues={{
              definition_type: '',
              definition: '',
              x_opencti_color: '',
              x_opencti_order: '',
            }}
            validationSchema={markingDefinitionValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={onClose}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <Field
                  component={TextField}
                  variant="standard"
                  name="definition_type"
                  label={t('Type')}
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="definition"
                  label={t('Definition')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={ColorPickerField}
                  name="x_opencti_color"
                  label={t('Color')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="x_opencti_order"
                  label={t('Order')}
                  fullWidth={true}
                  type="number"
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
}

MarkingDefinitionCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(MarkingDefinitionCreation);
