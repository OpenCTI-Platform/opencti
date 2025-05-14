import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import CreatorField from '../../common/form/CreatorField';
import { convertAuthorizedMembers, convertUser } from '../../../../utils/edition';
import Drawer from '../../common/drawer/Drawer';
import SwitchField from '../../../../components/fields/SwitchField';

export const ingestionTaxiiCollectionMutationFieldPatch = graphql`
  mutation IngestionTaxiiCollectionEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    ingestionTaxiiCollectionFieldPatch(id: $id, input: $input) {
      ...IngestionTaxiiCollectionEdition_ingestionTaxii
    }
  }
`;

const ingestionTaxiiCollectionValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  user_id: Yup.mixed().nullable(),
  confidence_to_score: Yup.bool().nullable(),
  restricted_members: Yup.array().required(t('This field is required')).min(1, t('This field is required')),
});

const IngestionTaxiiCollectionEditionContainer = ({
  t,
  open,
  handleClose,
  ingestionTaxiiCollection,
}) => {
  const handleSubmitField = (name, value) => {
    ingestionTaxiiCollectionValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        let finalValue = value;
        if (name === 'user_id') {
          finalValue = value?.value;
        }
        commitMutation({
          mutation: ingestionTaxiiCollectionMutationFieldPatch,
          variables: {
            id: ingestionTaxiiCollection.id,
            input: { key: name, value: finalValue || '' },
          },
        });
      })
      .catch(() => false);
  };

  const handleSubmitFieldOptions = (name, value) => ingestionTaxiiCollectionValidation(t)
    .validateAt(name, { [name]: value })
    .then(() => {
      commitMutation({
        mutation: ingestionTaxiiCollectionMutationFieldPatch,
        variables: {
          id: ingestionTaxiiCollection?.id,
          input: { key: name, value: value?.map(({ value: v }) => v) ?? '' },
        },
      });
    }).catch(() => false);
  const initialValues = R.pipe(
    R.assoc('user_id', convertUser(ingestionTaxiiCollection, 'user')),
    R.assoc('restricted_members', convertAuthorizedMembers(ingestionTaxiiCollection)),
    R.pick([
      'name',
      'description',
      'user_id',
      'restricted_members',
      'confidence_to_score',
    ]),
  )(ingestionTaxiiCollection);

  return (
    <Drawer
      title={t('Update a TAXII Push ingester')}
      open={open}
      onClose={handleClose}
    >
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={ingestionTaxiiCollectionValidation(t)}
      >
        {() => (
          <Form>
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
            <CreatorField
              name="user_id"
              label={t('User responsible for data creation (empty = System)')}
              onChange={handleSubmitField}
              containerStyle={fieldSpacingContainerStyle}
              showConfidence
            />
            <ObjectMembersField
              label={'Accessible for'}
              style={fieldSpacingContainerStyle}
              onChange={handleSubmitFieldOptions}
              multiple={true}
              name="restricted_members"
            />
            <Field
              component={SwitchField}
              onChange={handleSubmitField}
              type="checkbox"
              name="confidence_to_score"
              label={t('Copy confidence level to OpenCTI scores for indicators')}
              containerstyle={fieldSpacingContainerStyle}
            />
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

IngestionTaxiiCollectionEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  ingestionTaxiiCollection: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const IngestionTaxiiCollectionEditionFragment = createFragmentContainer(
  IngestionTaxiiCollectionEditionContainer,
  {
    ingestionTaxiiCollection: graphql`
      fragment IngestionTaxiiCollectionEdition_ingestionTaxii on IngestionTaxiiCollection {
        id
        name
        description
        confidence_to_score
        user {
          id
          entity_type
          name
        }
        authorized_members {
          id
          member_id
          name
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
)(IngestionTaxiiCollectionEditionFragment);
