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
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
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

const ObservedDataEditionOverviewComponent = (props) => {
  const { observedData, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();

  const basicShape = {
    first_observed: Yup.date()
      .required(t_i18n('This field is required'))
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    last_observed: Yup.date()
      .required(t_i18n('This field is required'))
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    number_observed: Yup.number(),
    confidence: Yup.number(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const observedDataValidator = useSchemaEditionValidation(
    'Observed-Data',
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
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      observedDataValidator
        .validateAt(name, { [name]: value })
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
                variant: 'standard',
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
                variant: 'standard',
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
              variant="standard"
              name="number_observed"
              label={t_i18n('Number observed')}
              fullWidth={true}
              style={{ marginTop: 20 }}
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="number_observed"
                />
              }
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
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdBy" />
              }
              onChange={editor.changeCreated}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={fieldSpacingContainerStyle}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldname="objectMarking"
                />
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
