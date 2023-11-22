import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { useSchemaEditionValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const positionMutationFieldPatch = graphql`
  mutation PositionEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    positionEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...PositionEditionOverview_position
        ...Position_position
      }
    }
  }
`;

export const positionEditionOverviewFocus = graphql`
  mutation PositionEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    positionEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const positionMutationRelationAdd = graphql`
  mutation PositionEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    positionEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...PositionEditionOverview_position
        }
      }
    }
  }
`;

const POSITION_TYPE = 'Position';

const positionMutationRelationDelete = graphql`
  mutation PositionEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    positionEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...PositionEditionOverview_position
      }
    }
  }
`;

const PositionEditionOverviewComponent = (props) => {
  const { position, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    POSITION_TYPE,
  );
  const basicShape = {
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable().max(5000, t_i18n('The value is too long')),
    confidence: Yup.number().nullable(),
    latitude: Yup.number()
      .typeError(t_i18n('This field must be a number'))
      .nullable(),
    longitude: Yup.number()
      .typeError(t_i18n('This field must be a number'))
      .nullable(),
    street_address: Yup.string()
      .nullable()
      .max(1000, t_i18n('The value is too long')),
    postal_code: Yup.string().nullable().max(1000, t_i18n('The value is too long')),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const positionValidator = useSchemaEditionValidation(POSITION_TYPE, basicShape);
  const queries = {
    fieldPatch: positionMutationFieldPatch,
    relationAdd: positionMutationRelationAdd,
    relationDelete: positionMutationRelationDelete,
    editionFocus: positionEditionOverviewFocus,
  };
  const editor = useFormEditor(
    position,
    enableReferences,
    queries,
    positionValidator,
  );
  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('confidence', parseInt(values.confidence, 10)),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: position.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };
  const handleSubmitField = (name, value) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      positionValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: position.id,
              input: {
                key: name,
                value: finalValue ?? '',
              },
            },
          });
        })
        .catch(() => false);
    }
  };
  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(position)),
    R.assoc('objectMarking', convertMarkings(position)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, position)),
    R.assoc('references', []),
    R.pick([
      'name',
      'references',
      'description',
      'latitude',
      'longitude',
      'street_address',
      'postal_code',
      'confidence',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(position);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={positionValidator}
      onSubmit={onSubmit}
    >
      {({
        submitForm,
        isSubmitting,
        setFieldValue,
        values,
        isValid,
        dirty,
      }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <AlertConfidenceForEntity entity={position} />
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Position"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <Field
            component={TextField}
            variant="standard"
            style={{ marginTop: 20 }}
            name="latitude"
            label={t_i18n('Latitude')}
            required={(mandatoryAttributes.includes('latitude'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="latitude" />
            }
          />
          <Field
            component={TextField}
            variant="standard"
            style={{ marginTop: 20 }}
            name="longitude"
            label={t_i18n('Longitude')}
            required={(mandatoryAttributes.includes('longitude'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="longitude" />
            }
          />
          <Field
            component={TextField}
            variant="standard"
            style={{ marginTop: 20 }}
            name="street_address"
            label={t_i18n('Street address')}
            required={(mandatoryAttributes.includes('street_address'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="street_address" />
            }
          />
          <Field
            component={TextField}
            variant="standard"
            style={{ marginTop: 20 }}
            name="postal_code"
            label={t_i18n('Postal code')}
            required={(mandatoryAttributes.includes('postal_code'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="postal_code" />
            }
          />
          {position.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Position"
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
              setFieldValue={setFieldValue}
              style={{ marginTop: 20 }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_opencti_workflow_id"
                />
              }
            />
          )}
          <CreatedByField
            name="createdBy"
            required={(mandatoryAttributes.includes('createdBy'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus context={context} fieldName="createdBy" />
            }
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={(mandatoryAttributes.includes('objectMarking'))}
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking" />
            }
            setFieldValue={setFieldValue}
            onChange={editor.changeMarking}
          />
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting || !isValid || !dirty}
              setFieldValue={setFieldValue}
              open={false}
              values={values.references}
              id={position.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(PositionEditionOverviewComponent, {
  position: graphql`
    fragment PositionEditionOverview_position on Position {
      id
      name
      latitude
      longitude
      street_address
      postal_code
      confidence
      entity_type
      description
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
    }
  `,
});
