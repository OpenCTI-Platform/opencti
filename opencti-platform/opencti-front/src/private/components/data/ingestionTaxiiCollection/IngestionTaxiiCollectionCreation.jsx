import React from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatorField from '../../common/form/CreatorField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';

const styles = (theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
});

const IngestionTaxiiCollectionCreationMutation = graphql`
  mutation IngestionTaxiiCollectionCreationMutation($input: IngestionTaxiiCollectionAddInput!) {
    ingestionTaxiiCollectionAdd(input: $input) {
      ...IngestionTaxiiCollectionLine_node
    }
  }
`;

const ingestionTaxiiCollectionCreationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  user_id: Yup.object().nullable(),
});

const IngestionTaxiiCreation = (props) => {
  const { t, classes } = props;
  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const input = {
      name: values.name,
      description: values.description,
      user_id: values.user_id?.value,
    };
    commitMutation({
      mutation: IngestionTaxiiCollectionCreationMutation,
      variables: {
        input,
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_ingestionTaxiiCollections',
          props.paginationOptions,
          'ingestionTaxiiCollectionAdd',
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  return (
    <Drawer
      title={t('Create a TAXII Push ingester')}
      variant={DrawerVariant.createWithPanel}
    >
      {({ onClose }) => (
        <Formik
          initialValues={{
            name: '',
            description: '',
            user_id: '',
          }}
          validationSchema={ingestionTaxiiCollectionCreationValidation(t)}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth={true}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t('Description')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <CreatorField
                name="user_id"
                label={t('User responsible for data creation (empty = System)')}
                containerStyle={fieldSpacingContainerStyle}
                showConfidence
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
};

IngestionTaxiiCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IngestionTaxiiCreation);
