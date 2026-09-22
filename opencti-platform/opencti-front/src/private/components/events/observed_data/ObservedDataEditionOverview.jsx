import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import StatusField from '../../common/form/StatusField';
import { buildDate, parse } from '../../../../utils/Time';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

export const observedDataMutationFieldPatch = graphql`
  mutation ObservedDataEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    observedDataEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...ObservedDataEditionOverview_observedData
      }
    }
  }
`;

export const observedDataEditionOverviewFocus = graphql`
  mutation ObservedDataEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    observedDataEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const observedDataMutationRelationAdd = graphql`
  mutation ObservedDataEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    observedDataEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...ObservedDataEditionOverview_observedData
        }
      }
    }
  }
`;

const observedDataMutationRelationDelete = graphql`
  mutation ObservedDataEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    observedDataEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...ObservedDataEditionOverview_observedData
      }
    }
  }
`;

const OBSERVED_DATA_TYPE = 'Observed-Data';
// Optional counters can be cleared from the form: an empty input removes the attribute
const OPTIONAL_COUNTERS = ['number_seen', 'max_distinct_count'];

const ObservedDataEditionOverviewComponent = (props) => {
  const { observedData, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(OBSERVED_DATA_TYPE);
  const basicShape = yupShapeConditionalRequired({
    first_observed: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    last_observed: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    // Counters are non-negative integers, mirroring the backend schema validation
    number_observed: Yup.number().integer(t_i18n('The value must be an integer'))
      .min(0, t_i18n('The value must be greater than or equal to 0')),
    number_seen: Yup.number().integer(t_i18n('The value must be an integer'))
      .nullable()
      .min(0, t_i18n('The value must be greater than or equal to 0')),
    max_distinct_count: Yup.number().integer(t_i18n('The value must be an integer'))
      .nullable()
      .min(0, t_i18n('The value must be greater than or equal to 0')),
    confidence: Yup.number(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  }, mandatoryAttributes);
  const observedDataValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
    ['objects'],
  );

  const queries = {
    fieldPatch: observedDataMutationFieldPatch,
    relationAdd: observedDataMutationRelationAdd,
    relationDelete: observedDataMutationRelationDelete,
    editionFocus: observedDataEditionOverviewFocus,
  };
  const editor = useFormEditor(
    observedData,
    enableReferences,
    queries,
    observedDataValidator,
  );

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('first_observed', parse(values.first_observed).format()),
      R.assoc('last_observed', parse(values.last_observed).format()),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: observedData.id,
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
      let valueToValidate = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      if (OPTIONAL_COUNTERS.includes(name) && value === '') {
        // Yup.number() rejects an empty string: validate the cleared counter as null, the patch sends an empty value
        finalValue = null;
        valueToValidate = null;
      }
      observedDataValidator
        .validateAt(name, { [name]: valueToValidate })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: observedData.id,
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
    R.assoc('createdBy', convertCreatedBy(observedData)),
    R.assoc('objectMarking', convertMarkings(observedData)),
    R.assoc('first_observed', buildDate(observedData.first_observed)),
    R.assoc('last_observed', buildDate(observedData.last_observed)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, observedData)),
    R.assoc('references', []),
    R.pick([
      'references',
      'first_observed',
      'last_observed',
      'number_observed',
      'number_seen',
      'max_distinct_count',
      'confidence',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(observedData);

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={observedDataValidator}
      validateOnChange={true}
      validateOnBlur={true}
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
        <div>
          <Form>
            <AlertConfidenceForEntity entity={observedData} />
            <Field
              component={DateTimePickerField}
              name="first_observed"
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              textFieldProps={{
                label: t_i18n('First observed'),
                required: (mandatoryAttributes.includes('first_observed')),
                variant: 'outlined',
                fullWidth: true,
                helperText: (
                  <SubscriptionFocus
                    context={context}
                    fieldName="first_observed"
                  />
                ),
              }}
            />
            <Field
              component={DateTimePickerField}
              name="last_observed"
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              textFieldProps={{
                label: t_i18n('Last observed'),
                required: (mandatoryAttributes.includes('last_observed')),
                variant: 'outlined',
                fullWidth: true,
                style: { marginTop: 20 },
                helperText: (
                  <SubscriptionFocus
                    context={context}
                    fieldName="last_observed"
                  />
                ),
              }}
            />
            <Field
              component={TextField}
              variant="outlined"
              name="number_observed"
              label={t_i18n('Number observed')}
              required={(mandatoryAttributes.includes('number_observed'))}
              fullWidth={true}
              className="mt-5"
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              helperText={(
                <SubscriptionFocus
                  context={context}
                  fieldName="number_observed"
                />
              )}
            />
            <Field
              component={TextField}
              variant="outlined"
              name="number_seen"
              label={t_i18n('Number seen')}
              required={(mandatoryAttributes.includes('number_seen'))}
              fullWidth={true}
              className="mt-5"
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              helperText={(
                <SubscriptionFocus
                  context={context}
                  fieldName="number_seen"
                />
              )}
            />
            <Field
              component={TextField}
              variant="outlined"
              name="max_distinct_count"
              label={t_i18n('Max distinct count')}
              required={(mandatoryAttributes.includes('max_distinct_count'))}
              fullWidth={true}
              className="mt-5"
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              helperText={(
                <SubscriptionFocus
                  context={context}
                  fieldName="max_distinct_count"
                />
              )}
            />
            <ConfidenceField
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              entityType="Observed-Data"
              containerStyle={fieldSpacingContainerStyle}
              editContext={context}
              variant="edit"
            />
            {observedData.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Observed-Data"
                onFocus={editor.changeFocus}
                onChange={handleSubmitField}
                setFieldValue={setFieldValue}
                style={{ marginTop: 20 }}
                helpertext={(
                  <SubscriptionFocus
                    context={context}
                    fieldName="x_opencti_workflow_id"
                  />
                )}
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
              helpertext={(
                <SubscriptionFocus
                  context={context}
                  fieldname="objectMarking"
                />
              )}
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
                id={observedData.id}
              />
            )}
          </Form>
        </div>
      )}
    </Formik>
  );
};

export default createFragmentContainer(ObservedDataEditionOverviewComponent, {
  observedData: graphql`
    fragment ObservedDataEditionOverview_observedData on ObservedData {
      id
      confidence
      entity_type
      first_observed
      last_observed
      number_observed
      number_seen
      max_distinct_count
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
      is_inferred
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
