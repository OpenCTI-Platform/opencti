import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { useTheme } from '@mui/styles';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertKillChainPhases, convertMarkings, convertStatus } from '../../../../utils/edition';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const attackPatternMutationFieldPatch = graphql`
  mutation AttackPatternEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    attackPatternEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...AttackPatternEditionOverview_attackPattern
        ...AttackPattern_attackPattern
      }
    }
  }
`;

export const attackPatternEditionOverviewFocus = graphql`
  mutation AttackPatternEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    attackPatternEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

export const attackPatternMutationRelationAdd = graphql`
  mutation AttackPatternEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    attackPatternEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...AttackPatternEditionOverview_attackPattern
        }
      }
    }
  }
`;

export const attackPatternMutationRelationDelete = graphql`
  mutation AttackPatternEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    attackPatternEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...AttackPatternEditionOverview_attackPattern
      }
    }
  }
`;

const AttackPatternEditionOverviewComponent = (props) => {
  const { attackPattern, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();
  const theme = useTheme();

  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    x_mitre_id: Yup.string().nullable(),
    description: Yup.string().nullable(),
    references: Yup.array(),
    confidence: Yup.number().nullable(),
    x_opencti_workflow_id: Yup.object(),
  };
  const attackPatternValidator = useSchemaEditionValidation(
    'Attack-Pattern',
    basicShape,
  );

  const queries = {
    fieldPatch: attackPatternMutationFieldPatch,
    relationAdd: attackPatternMutationRelationAdd,
    relationDelete: attackPatternMutationRelationDelete,
    editionFocus: attackPatternEditionOverviewFocus,
  };
  const editor = useFormEditor(
    attackPattern,
    enableReferences,
    queries,
    attackPatternValidator,
  );

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('confidence', parseInt(values.confidence, 10)),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: attackPattern.id,
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
      attackPatternValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: attackPattern.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(attackPattern)),
    R.assoc('killChainPhases', convertKillChainPhases(attackPattern)),
    R.assoc('objectMarking', convertMarkings(attackPattern)),
    R.assoc('x_opencti_workflow_id', convertStatus(t_i18n, attackPattern)),
    R.assoc('references', []),
    R.pick([
      'name',
      'x_mitre_id',
      'description',
      'createdBy',
      'killChainPhases',
      'confidence',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(attackPattern);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={{ ...initialValues, references: [] }}
      validationSchema={attackPatternValidator}
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
        <Form style={{ marginTop: theme.spacing(2) }}>
          <AlertConfidenceForEntity entity={attackPattern} />
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <Field
            component={TextField}
            name="x_mitre_id"
            label={t_i18n('External ID')}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="x_mitre_id" />
            }
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
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
            entityType="Attack-Pattern"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <KillChainPhasesField
            name="killChainPhases"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus
                context={context}
                fieldName="killChainPhases"
              />
            }
            onChange={editor.changeKillChainPhases}
          />
          {attackPattern.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Attack-Pattern"
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
              id={attackPattern.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(AttackPatternEditionOverviewComponent, {
  attackPattern: graphql`
    fragment AttackPatternEditionOverview_attackPattern on AttackPattern {
      id
      name
      x_mitre_id
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
      killChainPhases {
        id
        entity_type
        kill_chain_name
        phase_name
        x_opencti_order
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
