import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import OpenVocabField from '../../common/form/OpenVocabField';
import CreatorField from '../../common/form/CreatorField';
import { convertCreatedBy, convertMarkingsWithoutEdges, convertUser } from '../../../../utils/edition';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import Drawer from '../../common/drawer/Drawer';

export const ingestionRssMutationFieldPatch = graphql`
  mutation IngestionRssEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    ingestionRssFieldPatch(id: $id, input: $input) {
      ...IngestionRssEdition_ingestionRss
    }
  }
`;

const ingestionRssValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  uri: Yup.string().required(t('This field is required')),
  object_marking_refs: Yup.array().nullable(),
  report_types: Yup.array().nullable(),
  created_by_ref: Yup.mixed().nullable(),
  user_id: Yup.mixed().nullable(),
  current_state_date: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .nullable(),
});

const IngestionRssEditionContainer = ({
  t,
  handleClose,
  ingestionRss,
  open,
}) => {
  const handleSubmitField = (name, value) => {
    ingestionRssValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        let finalValue = value;
        if (name === 'created_by_ref') {
          finalValue = value?.value;
        }
        if (name === 'object_marking_refs') {
          finalValue = value?.map((n) => n.value);
        }
        if (name === 'user_id') {
          finalValue = value?.value;
        }
        commitMutation({
          mutation: ingestionRssMutationFieldPatch,
          variables: {
            id: ingestionRss.id,
            input: { key: name, value: finalValue || '' },
          },
        });
      })
      .catch(() => false);
  };
  const initialValues = R.pipe(
    R.assoc('report_types', ingestionRss.report_types ?? []),
    R.assoc(
      'created_by_ref',
      convertCreatedBy(ingestionRss, 'defaultCreatedBy'),
    ),
    R.assoc('user_id', convertUser(ingestionRss, 'user')),
    R.assoc(
      'object_marking_refs',
      convertMarkingsWithoutEdges(ingestionRss, 'defaultMarkingDefinitions'),
    ),
    R.pick([
      'name',
      'description',
      'uri',
      'user_id',
      'created_by_ref',
      'object_marking_refs',
      'report_types',
      'current_state_date',
    ]),
  )(ingestionRss);
  return (
    <Drawer
      title={t('Update a RSS ingester')}
      open={open}
      onClose={handleClose}
    >
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={ingestionRssValidation(t)}
      >
        {({ setFieldValue }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              fullWidth={true}
              onSubmit={handleSubmitField}
            />
            <Field
              component={TextField}
              variant="standard"
              name="description"
              label={t('Description')}
              fullWidth={true}
              style={fieldSpacingContainerStyle}
              onSubmit={handleSubmitField}
            />
            <Field
              component={TextField}
              variant="standard"
              name="uri"
              label={t('RSS feed URL')}
              fullWidth={true}
              onSubmit={handleSubmitField}
              style={fieldSpacingContainerStyle}
            />
            <CreatorField
              name="user_id"
              label={t('User responsible for data creation (empty = System)')}
              onChange={handleSubmitField}
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
              onChange={handleSubmitField}
            />
            <OpenVocabField
              label={t('Report types')}
              type="report_types_ov"
              name="report_types"
              onSubmit={handleSubmitField}
              onChange={setFieldValue}
              containerStyle={fieldSpacingContainerStyle}
              variant="edit"
              multiple={true}
            />
            <CreatedByField
              name="created_by_ref"
              style={fieldSpacingContainerStyle}
              onChange={handleSubmitField}
              setFieldValue={setFieldValue}
            />
            <ObjectMarkingField
              name="object_marking_refs"
              style={fieldSpacingContainerStyle}
              onChange={handleSubmitField}
              setFieldValue={setFieldValue}
            />
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

IngestionRssEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  ingestionRss: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const IngestionRssEditionFragment = createFragmentContainer(
  IngestionRssEditionContainer,
  {
    ingestionRss: graphql`
      fragment IngestionRssEdition_ingestionRss on IngestionRss {
        id
        name
        uri
        report_types
        ingestion_running
        current_state_date
        user {
          id
          entity_type
          name
        }
        defaultCreatedBy {
          id
          entity_type
          name
        }
        defaultMarkingDefinitions {
          id
          entity_type
          definition
          definition_type
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
)(IngestionRssEditionFragment);
