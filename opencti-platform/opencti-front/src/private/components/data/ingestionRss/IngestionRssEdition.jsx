import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
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
import {
  convertCreatedBy,
  convertMarkingsWithoutEdges,
  convertUser,
} from '../../../../utils/edition';

const styles = (theme) => ({
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
  container: {
    padding: '10px 20px 20px 20px',
  },
  title: {
    float: 'left',
  },
});

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
  created_by_ref: Yup.object().nullable(),
  user_id: Yup.object().nullable(),
});

const IngestionRssEditionContainer = ({
  t,
  classes,
  handleClose,
  ingestionRss,
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
    R.assoc('created_by_ref', convertCreatedBy(ingestionRss, 'defaultCreatedBy')),
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
    ]),
  )(ingestionRss);
  return (
    <>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6">{t('Update a RSS ingester')}</Typography>
      </div>
      <div className={classes.container}>
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
              />
              <ObjectMarkingField
                name="object_marking_refs"
                style={fieldSpacingContainerStyle}
                onChange={handleSubmitField}
              />
            </Form>
          )}
        </Formik>
      </div>
    </>
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
  withStyles(styles, { withTheme: true }),
)(IngestionRssEditionFragment);
