import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import CustomFieldValuesEdition from '@components/common/custom_fields/CustomFieldValuesEdition';
import { GenericContext } from '@components/common/model/GenericContextModel';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import { useFormatter } from '../../../../components/i18n';
import { convertCreatedBy, convertExternalReferences, convertKillChainPhases, convertMarkings, convertStatus } from '../../../../utils/edition';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { adaptFieldValue } from '../../../../utils/String';
import { buildDate, parse } from '../../../../utils/Time';
import { useDynamicSchemaEditionValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import StatusField from '../../common/form/StatusField';
import CommitMessage from '../../common/form/CommitMessage';
import ConfidenceField from '../../common/form/ConfidenceField';
import OpenVocabField from '../../common/form/OpenVocabField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import StixCoreObjectsField from '../../common/form/StixCoreObjectsField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { ProcedureEditionOverview_procedure$key } from './__generated__/ProcedureEditionOverview_procedure.graphql';
import { saveProcedureObservables } from './ProcedureObservablesEditor';
import ProcedureComponentsField, { canSaveComponents, ComponentRow } from './ProcedureComponentsField';
import { createTextObservable, saveProcedureComponents, searchObservables } from './ProcedureComponentsEditor';

const procedureMutationFieldPatch = graphql`
  mutation ProcedureEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    procedureFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      ...ProcedureEditionOverview_procedure
      ...Procedure_procedure
    }
  }
`;

export const procedureEditionOverviewFocus = graphql`
  mutation ProcedureEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    procedureContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const procedureMutationRelationAdd = graphql`
  mutation ProcedureEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    procedureRelationAdd(id: $id, input: $input) {
      from {
        ...ProcedureEditionOverview_procedure
        ...Procedure_procedure
      }
    }
  }
`;

const procedureMutationRelationDelete = graphql`
  mutation ProcedureEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    procedureRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      ...ProcedureEditionOverview_procedure
      ...Procedure_procedure
    }
  }
`;

const ProcedureEditionOverviewFragment = graphql`
  fragment ProcedureEditionOverview_procedure on Procedure {
    id
    ...CustomFieldValuesEdition_values @relay(mask: false)
    name
    confidence
    entity_type
    description
    x_procedure_type
    x_mitre_platforms
    first_observed
    last_observed
    x_execution_start
    x_execution_end
    killChainPhases {
      id
      entity_type
      kill_chain_name
      phase_name
      x_opencti_order
    }
    procedureCommand {
      id
      entity_type
      observable_value
    }
    procedureComponents {
      component_index
      component_type
      observable {
        id
        entity_type
        observable_value
      }
    }
    procedureObservables(first: 100) {
      edges {
        node {
          id
          entity_type
          observable_value
        }
      }
    }
    procedureSources {
      id
      entity_type
      name
    }
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
    externalReferences {
      edges {
        node {
          id
          source_name
          description
          url
          external_id
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
`;

const PROCEDURE_TYPE = 'Procedure';

const toIds = (value: FieldOption | FieldOption[] | null | undefined) => [value ?? []].flat().map((option) => option.value);

// Ids put in and taken out of a multiple selection.
const diffIds = (previous: FieldOption[], next: FieldOption[]) => {
  const previousIds = toIds(previous);
  const nextIds = toIds(next);
  return {
    added: nextIds.filter((id) => !previousIds.includes(id)),
    removed: previousIds.filter((id) => !nextIds.includes(id)),
  };
};

// Patch of a multiple ref from its previous to its next selection: add and remove the changed ids, never replace.
const buildRefsPatch = (key: string, previous: FieldOption[], next: FieldOption[]) => {
  const { added, removed } = diffIds(previous, next);
  return [
    ...(added.length > 0 ? [{ key, value: added, operation: 'add' as const }] : []),
    ...(removed.length > 0 ? [{ key, value: removed, operation: 'remove' as const }] : []),
  ];
};

interface ProcedureEditionOverviewProps {
  data: ProcedureEditionOverview_procedure$key;
  context?: readonly (GenericContext | null)[] | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface ProcedureEditionFormData {
  name: string;
  description: string | null;
  confidence: number | undefined;
  x_procedure_type: string | null;
  x_mitre_platforms: string[];
  first_observed: Date | null;
  last_observed: Date | null;
  x_execution_start: Date | null;
  x_execution_end: Date | null;
  killChainPhases: FieldOption[];
  procedureObservables: FieldOption[];
  procedureCommand: FieldOption | null;
  procedureSources: FieldOption[];
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  externalReferences: FieldOption[];
  x_opencti_workflow_id: FieldOption;
  message?: string;
  references?: FieldOption[];
}

const ProcedureEditionOverview: FunctionComponent<ProcedureEditionOverviewProps> = ({
  data,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const procedure = useFragment(ProcedureEditionOverviewFragment, data);
  const initialComponents: ComponentRow[] = [...(procedure.procedureComponents ?? [])]
    .sort((a, b) => a.component_index - b.component_index)
    .map((c) => ({ ...c.observable, type: c.component_type === 'primary' ? 'primary' : 'secondary' }));
  const [components, setComponents] = useState<ComponentRow[]>(initialComponents);
  const componentsInput = (rows: ComponentRow[]) => rows.map(({ id, type }) => ({ id, type }));
  const componentsChanged = (rows: ComponentRow[]) => JSON.stringify(componentsInput(rows)) !== JSON.stringify(componentsInput(initialComponents));
  // Like the drawer's other fields, the sequence saves as it changes, and only while every row is valid.
  // Under enforced references it saves with the form's commit.
  const handleComponentsChange = (rows: ComponentRow[]) => {
    setComponents(rows);
    if (!enableReferences && canSaveComponents(rows)) {
      saveProcedureComponents(procedure.id, componentsInput(rows));
    }
  };

  const { mandatoryAttributes } = useIsMandatoryAttribute(PROCEDURE_TYPE);
  const dateSchema = Yup.date()
    .nullable()
    .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'));
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    x_procedure_type: Yup.string().nullable(),
    x_mitre_platforms: Yup.array().nullable(),
    first_observed: dateSchema,
    last_observed: dateSchema,
    x_execution_start: dateSchema,
    x_execution_end: dateSchema,
    killChainPhases: Yup.array().nullable(),
    procedureObservables: Yup.array().nullable(),
    procedureCommand: Yup.object().nullable(),
    procedureSources: Yup.array().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);
  const procedureValidator = useDynamicSchemaEditionValidation(mandatoryAttributes, basicShape);

  const queries = {
    fieldPatch: procedureMutationFieldPatch,
    relationAdd: procedureMutationRelationAdd,
    relationDelete: procedureMutationRelationDelete,
    editionFocus: procedureEditionOverviewFocus,
  };
  const editor = useFormEditor(procedure as GenericData, enableReferences, queries, procedureValidator);

  const initialValues: ProcedureEditionFormData = {
    name: procedure.name,
    description: procedure.description ?? '',
    confidence: procedure.confidence ?? undefined,
    x_procedure_type: procedure.x_procedure_type ?? null,
    x_mitre_platforms: [...(procedure.x_mitre_platforms ?? [])],
    first_observed: buildDate(procedure.first_observed),
    last_observed: buildDate(procedure.last_observed),
    x_execution_start: buildDate(procedure.x_execution_start),
    x_execution_end: buildDate(procedure.x_execution_end),
    killChainPhases: convertKillChainPhases(procedure),
    procedureObservables: (procedure.procedureObservables?.edges ?? [])
      .map(({ node }) => ({ value: node.id, label: node.observable_value, type: node.entity_type })),
    procedureCommand: procedure.procedureCommand
      ? { value: procedure.procedureCommand.id, label: procedure.procedureCommand.observable_value, type: procedure.procedureCommand.entity_type }
      : null,
    procedureSources: (procedure.procedureSources ?? [])
      .flatMap((source) => (source ? [{ value: source.id, label: source.name, type: source.entity_type }] : [])),
    createdBy: convertCreatedBy(procedure) as FieldOption,
    objectMarking: convertMarkings(procedure),
    externalReferences: convertExternalReferences(procedure),
    x_opencti_workflow_id: convertStatus(t_i18n, procedure) as FieldOption,
    references: [],
  };

  const onSubmit: FormikConfig<ProcedureEditionFormData>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, procedureObservables, procedureSources, externalReferences, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);
    const formatDate = (date: Date | null) => (date ? parse(date).format() : null);

    const inputValues = [
      ...Object.entries({
        ...otherValues,
        createdBy: values.createdBy?.value,
        x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
        objectMarking: toIds(values.objectMarking),
        killChainPhases: toIds(values.killChainPhases),
        procedureCommand: toIds(values.procedureCommand),
        first_observed: formatDate(values.first_observed),
        last_observed: formatDate(values.last_observed),
        x_execution_start: formatDate(values.x_execution_start),
        x_execution_end: formatDate(values.x_execution_end),
      }).map(([key, value]) => ({ key, value: adaptFieldValue(value) })),
      ...buildRefsPatch('procedureSources', initialValues.procedureSources, procedureSources),
      ...buildRefsPatch('externalReferences', initialValues.externalReferences, externalReferences),
    ];

    if (canSaveComponents(components) && componentsChanged(components)) {
      saveProcedureComponents(procedure.id, componentsInput(components));
    }
    // Observables are has-observable relationships: saved apart, they cannot carry the commit message.
    saveProcedureObservables(procedure.id, diffIds(initialValues.procedureObservables, procedureObservables));
    editor.fieldPatch({
      variables: {
        id: procedure.id,
        input: inputValues,
        commitMessage: commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name: string, value: string | string[] | number | number[] | FieldOption | null) => {
    if (!enableReferences) {
      const finalValue = name === 'x_opencti_workflow_id' ? (value as FieldOption).value : value;
      procedureValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: procedure.id,
              input: [{ key: name, value: finalValue ?? '' }],
            },
          });
        })
        .catch(() => false);
    }
  };

  // The command is a single ref, which the backend replaces whatever the operation.
  // Multiple refs are patched with the added and removed ids only: the form loads one page of them.
  const handleSubmitRefs = (name: string, value: FieldOption | FieldOption[] | null) => {
    if (!enableReferences) {
      if (name === 'procedureObservables') {
        saveProcedureObservables(procedure.id, diffIds(initialValues.procedureObservables, [value ?? []].flat()));
        return;
      }
      const input = name === 'procedureCommand'
        ? [{ key: name, value: toIds(value) }]
        : buildRefsPatch(name, initialValues.procedureSources, [value ?? []].flat());
      if (input.length === 0) return;
      procedureValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: procedure.id,
              input,
            },
          });
        })
        .catch(() => false);
    }
  };

  const dateField = (name: string, label: string) => (
    <Field
      component={DateTimePickerField}
      name={name}
      onFocus={editor.changeFocus}
      onSubmit={handleSubmitField}
      textFieldProps={{
        label,
        required: mandatoryAttributes.includes(name),
        variant: 'outlined',
        fullWidth: true,
        style: { marginTop: 20 },
        helperText: <SubscriptionFocus context={context} fieldName={name} />,
      }}
    />
  );

  return (
    <Formik<ProcedureEditionFormData>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={procedureValidator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
    >
      {({ submitForm, isSubmitting, setFieldValue, values, isValid, dirty }) => (
        <Form>
          <AlertConfidenceForEntity entity={procedure} />
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            required={mandatoryAttributes.includes('name')}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={<SubscriptionFocus context={context} fieldName="name" />}
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType={PROCEDURE_TYPE}
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={mandatoryAttributes.includes('description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            uploadEntityId={procedure.id}
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={<SubscriptionFocus context={context} fieldName="description" />}
          />
          <OpenVocabField
            label={t_i18n('Procedure type')}
            type="procedure_type_ov"
            name="x_procedure_type"
            required={mandatoryAttributes.includes('x_procedure_type')}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={false}
            editContext={context}
          />
          <OpenVocabField
            label={t_i18n('Platforms')}
            type="platforms_ov"
            name="x_mitre_platforms"
            required={mandatoryAttributes.includes('x_mitre_platforms')}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={true}
            editContext={context}
          />
          <KillChainPhasesField
            name="killChainPhases"
            required={mandatoryAttributes.includes('killChainPhases')}
            style={fieldSpacingContainerStyle}
            helpertext={<SubscriptionFocus context={context} fieldName="killChainPhases" />}
            onChange={editor.changeKillChainPhases}
          />
          <StixCoreObjectsField
            name="procedureObservables"
            label={t_i18n('Observables')}
            types={['Stix-Cyber-Observable']}
            required={mandatoryAttributes.includes('procedureObservables')}
            style={fieldSpacingContainerStyle}
            onChange={handleSubmitRefs}
          />
          <div style={fieldSpacingContainerStyle}>
            <ProcedureComponentsField
              rows={components}
              onChange={handleComponentsChange}
              search={searchObservables}
              createText={createTextObservable}
            />
          </div>
          <StixCoreObjectsField
            name="procedureCommand"
            label={t_i18n('Command')}
            types={['Process']}
            multiple={false}
            required={mandatoryAttributes.includes('procedureCommand')}
            style={fieldSpacingContainerStyle}
            onChange={handleSubmitRefs}
          />
          <StixCoreObjectsField
            name="procedureSources"
            label={t_i18n('Sources')}
            types={['Identity']}
            required={mandatoryAttributes.includes('procedureSources')}
            style={fieldSpacingContainerStyle}
            onChange={handleSubmitRefs}
          />
          {dateField('first_observed', t_i18n('First observed'))}
          {dateField('last_observed', t_i18n('Last observed'))}
          {dateField('x_execution_start', t_i18n('Execution start'))}
          {dateField('x_execution_end', t_i18n('Execution end'))}
          {procedure.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              required={mandatoryAttributes.includes('x_opencti_workflow_id')}
              type={PROCEDURE_TYPE}
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
              setFieldValue={setFieldValue}
              style={{ marginTop: 20 }}
              helpertext={<SubscriptionFocus context={context} fieldName="x_opencti_workflow_id" />}
            />
          )}
          <CreatedByField
            name="createdBy"
            required={mandatoryAttributes.includes('createdBy')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            helpertext={<SubscriptionFocus context={context} fieldName="createdBy" />}
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={mandatoryAttributes.includes('objectMarking')}
            style={fieldSpacingContainerStyle}
            helpertext={<SubscriptionFocus context={context} fieldname="objectMarking" />}
            setFieldValue={setFieldValue}
            onChange={editor.changeMarking}
          />
          <ExternalReferencesField
            name="externalReferences"
            required={mandatoryAttributes.includes('externalReferences')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
            onChange={editor.changeExternalReferences}
          />
          <CustomFieldValuesEdition
            entityType={procedure.entity_type}
            entityId={procedure.id}
            values={procedure.customFieldValues ?? []}
            fieldPatch={editor.fieldPatch}
            enableReferences={enableReferences}
          />
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting || !isValid || !dirty}
              setFieldValue={setFieldValue}
              open={false}
              values={values.references}
              id={procedure.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default ProcedureEditionOverview;
