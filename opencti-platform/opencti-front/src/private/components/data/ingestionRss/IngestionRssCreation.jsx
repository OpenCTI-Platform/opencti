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
import OpenVocabField from '../../common/form/OpenVocabField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { insertNode } from '../../../../utils/store';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useSchemaCreationValidation, useMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';

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

const OBJECT_TYPE = 'IngestionRss';

const IngestionRssCreation = (props) => {
  const { t, classes } = props;

  const basicShape = {
    name: Yup.string(),
    description: Yup.string().nullable(),
    uri: Yup.string(),
    object_marking_refs: Yup.array().nullable(),
    report_types: Yup.array().nullable(),
    created_by_ref: Yup.object().nullable(),
    user_id: Yup.object().nullable(),
    current_state_date: Yup.date()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
  };
  const mandatoryAttributes = useMandatorySchemaAttributes(OBJECT_TYPE);
  const validator = useSchemaCreationValidation(
    OBJECT_TYPE,
    basicShape,
  );

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const input = {
      name: values.name,
      description: values.description,
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
      variant={DrawerVariant.createWithPanel}
    >
      {({ onClose }) => (
        <Formik
          initialValues={{
            name: '',
            description: '',
            uri: '',
            report_types: [],
            user_id: '',
            created_by_ref: '',
            objectMarking: [],
            current_state_date: null,
          }}
          validationSchema={validator}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                required={(mandatoryAttributes.includes('name'))}
                fullWidth={true}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t('Description')}
                required={(mandatoryAttributes.includes('description'))}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={TextField}
                variant="standard"
                name="uri"
                label={t('RSS Feed URL')}
                required={(mandatoryAttributes.includes('uri'))}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <CreatorField
                name="user_id"
                label={t('User responsible for data creation (empty = System)')}
                required={(mandatoryAttributes.includes('user_id'))}
                containerStyle={fieldSpacingContainerStyle}
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
                required={(mandatoryAttributes.includes('current_state_date'))}
              />
              <OpenVocabField
                label={t('Default report types')}
                type="report_types_ov"
                name="report_types"
                required={(mandatoryAttributes.includes('report_types'))}
                onChange={(name, value) => setFieldValue(name, value)}
                containerStyle={fieldSpacingContainerStyle}
                multiple={true}
              />
              <CreatedByField
                name="created_by_ref"
                label={t('Default author')}
                required={(mandatoryAttributes.includes('created_by_ref'))}
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
              <ObjectMarkingField
                label={t('Default marking definitions')}
                name="object_marking_refs"
                required={(mandatoryAttributes.includes('object_marking_refs'))}
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
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
