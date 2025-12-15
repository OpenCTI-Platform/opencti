import React from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import * as R from 'ramda';

import IngestionSchedulingField from '../IngestionSchedulingField';
import Drawer from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatorField from '../../common/form/CreatorField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../../common/form/OpenVocabField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { insertNode } from '../../../../utils/store';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

const styles = (theme) => ({
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
    padding: '20px 0px 20px 60px',
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
  title: {
    float: 'left',
  },
});

const IngestionRssCreationMutation = graphql`
  mutation IngestionRssCreationMutation($input: IngestionRssAddInput!) {
    ingestionRssAdd(input: $input) {
      ...IngestionRssLine_node
    }
  }
`;

const ingestionRssCreationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  uri: Yup.string().required(t('This field is required')),
  object_marking_refs: Yup.array().nullable(),
  report_types: Yup.array().nullable(),
  created_by_ref: Yup.object().nullable(),
  user_id: Yup.object().nullable(),
  current_state_date: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .nullable(),
});

const CreateIngestionRssControlledDial = (props) => (
  <CreateEntityControlledDial
    entityType="IngestionRss"
    {...props}
  />
);

const IngestionRssCreation = (props) => {
  const { t, classes } = props;

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const input = {
      name: values.name,
      description: values.description,
      scheduling_period: values.scheduling_period,
      uri: values.uri,
      report_types: values.report_types,
      user_id: values.user_id?.value,
      current_state_date: values.current_state_date,
      created_by_ref: values.created_by_ref?.value,
      object_marking_refs: values.object_marking_refs?.map((v) => v.value),
    };
    commitMutation({
      mutation: IngestionRssCreationMutation,
      variables: {
        input,
      },
      updater: (store) => {
        insertNode(store, 'Pagination_ingestionRsss', props.paginationOptions, 'ingestionRssAdd');
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
      title={t('Create a RSS ingester')}
      controlledDial={CreateIngestionRssControlledDial}
    >
      {({ onClose }) => (
        <Formik
          initialValues={{
            name: '',
            description: '',
            uri: '',
            scheduling_period: 'PT1H',
            report_types: [],
            user_id: '',
            created_by_ref: '',
            objectMarking: [],
            current_state_date: null,
          }}
          validationSchema={ingestionRssCreationValidation(t)}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
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
              <IngestionSchedulingField />
              <Field
                component={TextField}
                variant="standard"
                name="uri"
                label={t('RSS Feed URL')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <CreatorField
                name="user_id"
                label={t('User responsible for data creation (empty = System)')}
                containerStyle={fieldSpacingContainerStyle}
                showConfidence
              />
              <Field
                component={DateTimePickerField}
                name="current_state_date"
                textFieldProps={{
                  label: t(
                    'Import from date (empty = all RSS feed possible items)',
                  ),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <OpenVocabField
                label={t('Default report types')}
                type="report_types_ov"
                name="report_types"
                onChange={(name, value) => setFieldValue(name, value)}
                containerStyle={fieldSpacingContainerStyle}
                multiple={true}
              />
              <CreatedByField
                name="created_by_ref"
                label={t('Default author')}
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
              <ObjectMarkingField
                label={t('Default marking definitions')}
                name="object_marking_refs"
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
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

IngestionRssCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IngestionRssCreation);
