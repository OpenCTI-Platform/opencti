import React from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Drawer from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatorField from '../../common/form/CreatorField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import SwitchField from '../../../../components/fields/SwitchField';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

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
  confidence_to_score: Yup.bool().nullable(),
  authorized_members: Yup.array().required(t('This field is required')).min(1, t('This field is required')),
});

const CreateIngestionTaxiiCollectionControlledDial = (props) => (
  <CreateEntityControlledDial
    entityType="IngestionTaxiiCollection"
    {...props}
  />
);

const IngestionTaxiiCollectionCreation = (props) => {
  const { t, classes } = props;

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const authorized_members = values.authorized_members.map(({ value }) => ({
      id: value,
      access_right: 'view',
    }));
    const input = {
      name: values.name,
      description: values.description,
      confidence_to_score: values.confidence_to_score,
      user_id: values.user_id?.value,
      authorized_members,
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
      controlledDial={CreateIngestionTaxiiCollectionControlledDial}
    >
      {({ onClose }) => (
        <Formik
          initialValues={{
            name: '',
            description: '',
            user_id: '',
            confidence_to_score: false,
          }}
          validationSchema={ingestionTaxiiCollectionCreationValidation(t)}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, setFieldValue, isSubmitting }) => (
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
              <ObjectMembersField
                label="Accessible for"
                style={fieldSpacingContainerStyle}
                onChange={setFieldValue}
                multiple={true}
                name="authorized_members"
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="confidence_to_score"
                label={t('Copy confidence level to OpenCTI scores for indicators')}
                containerstyle={fieldSpacingContainerStyle}
              />
              <div className={classes.buttons}>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Cancel')}
                </Button>
                <Button
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

IngestionTaxiiCollectionCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IngestionTaxiiCollectionCreation);
