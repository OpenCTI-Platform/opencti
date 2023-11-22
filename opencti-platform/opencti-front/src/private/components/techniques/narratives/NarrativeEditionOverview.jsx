import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import { useSchemaEditionValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const narrativeMutationFieldPatch = graphql`
  mutation NarrativeEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    narrativeFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      ...NarrativeEditionOverview_narrative
      ...Narrative_narrative
    }
  }
`;

export const narrativeEditionOverviewFocus = graphql`
  mutation NarrativeEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    narrativeContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const narrativeMutationRelationAdd = graphql`
  mutation NarrativeEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    narrativeRelationAdd(id: $id, input: $input) {
      from {
        ...NarrativeEditionOverview_narrative
      }
    }
  }
`;

const narrativeMutationRelationDelete = graphql`
  mutation NarrativeEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    narrativeRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      ...NarrativeEditionOverview_narrative
    }
  }
`;

const NARRATIVE_TYPE = 'Narrative';

const NarrativeEditionOverviewComponent = (props) => {
  const { narrative, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    NARRATIVE_TYPE,
  );
  const basicShape = {
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    references: Yup.array(),
    confidence: Yup.number().nullable(),
    x_opencti_workflow_id: Yup.object(),
  };
  const narrativeValidator = useSchemaEditionValidation(
    NARRATIVE_TYPE,
    basicShape,
  );

  const queries = {
    fieldPatch: narrativeMutationFieldPatch,
    relationAdd: narrativeMutationRelationAdd,
    relationDelete: narrativeMutationRelationDelete,
    editionFocus: narrativeEditionOverviewFocus,
  };
  const editor = useFormEditor(
    narrative,
    enableReferences,
    queries,
    narrativeValidator,
  );

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('confidence', parseInt(values.confidence, 10)),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: narrative.id,
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
      narrativeValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: narrative.id,
              input: { key: name, value: finalValue },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(narrative)),
    R.assoc('objectMarking', convertMarkings(narrative)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, narrative)),
    R.assoc('references', []),
    R.pick([
      'name',
      'references',
      'description',
      'createdBy',
      'objectMarking',
      'confidence',
      'x_opencti_workflow_id',
    ]),
  )(narrative);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={narrativeValidator}
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
          <AlertConfidenceForEntity entity={narrative} />
          <Field
            component={TextField}
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
            entityType="Narratives"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          {narrative.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Narrative"
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
              id={narrative.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(NarrativeEditionOverviewComponent, {
  narrative: graphql`
    fragment NarrativeEditionOverview_narrative on Narrative {
      id
      name
      description
      confidence
      entity_type
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
