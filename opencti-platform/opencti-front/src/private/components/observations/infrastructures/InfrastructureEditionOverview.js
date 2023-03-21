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
import MarkDownField from '../../../../components/MarkDownField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import {
  convertCreatedBy,
  convertKillChainPhases,
  convertMarkings,
  convertStatus,
} from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { buildDate, parse } from '../../../../utils/Time';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';

const infrastructureMutationFieldPatch = graphql`
  mutation InfrastructureEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    infrastructureEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...InfrastructureEditionOverview_infrastructure
        ...Infrastructure_infrastructure
      }
    }
  }
`;

export const infrastructureEditionOverviewFocus = graphql`
  mutation InfrastructureEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    infrastructureEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const infrastructureMutationRelationAdd = graphql`
  mutation InfrastructureEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    infrastructureEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...InfrastructureEditionOverview_infrastructure
        }
      }
    }
  }
`;

const infrastructureMutationRelationDelete = graphql`
  mutation InfrastructureEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    infrastructureEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...InfrastructureEditionOverview_infrastructure
      }
    }
  }
`;

const InfrastructureEditionOverviewComponent = (props) => {
  const { infrastructure, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    infrastructure_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    first_seen: Yup.date()
      .nullable()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    last_seen: Yup.date()
      .nullable()
      .min(
        Yup.ref('first_seen'),
        "The last seen date can't be before first seen date",
      )
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const infrastructureValidator = useSchemaEditionValidation(
    'Infrastructure',
    basicShape,
  );

  const queries = {
    fieldPatch: infrastructureMutationFieldPatch,
    relationAdd: infrastructureMutationRelationAdd,
    relationDelete: infrastructureMutationRelationDelete,
    editionFocus: infrastructureEditionOverviewFocus,
  };
  const editor = useFormEditor(
    infrastructure,
    enableReferences,
    queries,
    infrastructureValidator,
  );

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
      R.assoc('infrastructure_types', values.infrastructure_types),
      R.assoc(
        'first_seen',
        values.first_seen ? parse(values.first_seen).format() : null,
      ),
      R.assoc(
        'last_seen',
        values.last_seen ? parse(values.last_seen).format() : null,
      ),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: infrastructure.id,
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
      infrastructureValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: infrastructure.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = R.pipe(
    R.assoc('createdBy', convertCreatedBy(infrastructure)),
    R.assoc('killChainPhases', convertKillChainPhases(infrastructure)),
    R.assoc('objectMarking', convertMarkings(infrastructure)),
    R.assoc('x_opencti_workflow_id', convertStatus(t, infrastructure)),
    R.assoc('first_seen', buildDate(infrastructure.first_seen)),
    R.assoc('last_seen', buildDate(infrastructure.last_seen)),
    R.assoc(
      'infrastructure_types',
      infrastructure.infrastructure_types
        ? infrastructure.infrastructure_types
        : [],
    ),
    R.assoc('references', []),
    R.pick([
      'name',
      'references',
      'description',
      'infrastructure_types',
      'confidence',
      'first_seen',
      'last_seen',
      'createdBy',
      'killChainPhases',
      'objectMarking',
      'x_opencti_workflow_id',
      'confidence',
    ]),
  )(infrastructure);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={infrastructureValidator}
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
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <OpenVocabField
            label={t('Infrastructure types')}
            type="infrastructure-type-ov"
            name="infrastructure_types"
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={true}
            editContext={context}
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Infrastructure"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <Field
            component={DateTimePickerField}
            name="first_seen"
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            TextFieldProps={{
              label: t('First seen'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
              helperText: (
                <SubscriptionFocus context={context} fieldName="first_seen" />
              ),
            }}
          />
          <Field
            component={DateTimePickerField}
            name="last_seen"
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            TextFieldProps={{
              label: t('Last seen'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
              helperText: (
                <SubscriptionFocus context={context} fieldName="last_seen" />
              ),
            }}
          />
          <KillChainPhasesField
            name="killChainPhases"
            style={{ marginTop: 20, width: '100%' }}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus
                context={context}
                fieldName="killChainPhases"
              />
            }
            onChange={editor.changeKillChainPhases}
          />
          <Field
            component={MarkDownField}
            name="description"
            label={t('Description')}
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
          {infrastructure.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Infrastructure"
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
            style={{ marginTop: 20, width: '100%' }}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus context={context} fieldName="createdBy" />
            }
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={{ marginTop: 20, width: '100%' }}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking" />
            }
            onChange={editor.changeMarking}
          />
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting || !isValid || !dirty}
              setFieldValue={setFieldValue}
              open={false}
              values={values.references}
              id={infrastructure.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(InfrastructureEditionOverviewComponent, {
  infrastructure: graphql`
    fragment InfrastructureEditionOverview_infrastructure on Infrastructure {
      id
      name
      description
      confidence
      first_seen
      last_seen
      infrastructure_types
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      killChainPhases {
        edges {
          node {
            id
            kill_chain_name
            phase_name
            x_opencti_order
          }
        }
      }
      objectMarking {
        edges {
          node {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
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
