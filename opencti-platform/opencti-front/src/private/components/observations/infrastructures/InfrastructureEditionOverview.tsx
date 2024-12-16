import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { convertCreatedBy, convertKillChainPhases, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { buildDate, formatDate } from '../../../../utils/Time';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { InfrastructureEditionOverview_infrastructure$key } from './__generated__/InfrastructureEditionOverview_infrastructure.graphql';
import { Option } from '../../common/form/ReferenceField';
import { GenericContext } from '../../common/model/GenericContextModel';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

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
    $input: StixRefRelationshipAddInput!
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

export const infrastructureEditionOverviewFragment = graphql`
  fragment InfrastructureEditionOverview_infrastructure on Infrastructure {
    id
    name
    description
    confidence
    entity_type
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
`;

interface InfrastructureEditionOverviewProps {
  infrastructureData: InfrastructureEditionOverview_infrastructure$key,
  context?: readonly (GenericContext | null)[] | null;
  enableReferences: boolean
  handleClose: () => void
}

interface InfrastructureEditionFormValues {
  message?: string
  references?: Option[]
  createdBy: Option | undefined
  x_opencti_workflow_id: Option
  objectMarking?: Option[]
  killChainPhases?: Option[];
  first_seen: null | Date;
  last_seen: null | Date;
  confidence: number | null | undefined;
}

const InfrastructureEditionOverviewComponent: FunctionComponent<InfrastructureEditionOverviewProps> = ({
  infrastructureData,
  context,
  enableReferences,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const infrastructure = useFragment(infrastructureEditionOverviewFragment, infrastructureData);

  const basicShape = {
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    infrastructure_types: Yup.array().nullable(),
    confidence: Yup.number().nullable(),
    first_seen: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    last_seen: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
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
    infrastructure as GenericData,
    enableReferences,
    queries,
    infrastructureValidator,
  );

  const onSubmit: FormikConfig<InfrastructureEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);

    const inputValues = Object.entries({
      ...otherValues,
      confidence: parseInt(String(values.confidence), 10),
      createdBy: values.createdBy?.value,
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
      killChainPhases: (values.killChainPhases ?? []).map(({ value }) => value),
      first_seen: formatDate(values.first_seen),
      last_seen: formatDate(values.last_seen),
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    editor.fieldPatch({
      variables: {
        id: infrastructure.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name: string, value: Option | string | string[] | number | number[] | null) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as Option).value;
      }
      infrastructureValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: infrastructure.id,
              input: { key: name, value: finalValue || '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = {
    name: infrastructure.name,
    description: infrastructure.description,
    createdBy: convertCreatedBy(infrastructure) as Option,
    objectMarking: convertMarkings(infrastructure),
    killChainPhases: convertKillChainPhases(infrastructure),
    x_opencti_workflow_id: convertStatus(t_i18n, infrastructure) as Option,
    confidence: infrastructure.confidence,
    first_seen: buildDate(infrastructure.first_seen),
    last_seen: buildDate(infrastructure.last_seen),
    infrastructure_types: infrastructure.infrastructure_types ?? [],
    references: [],
  };
  return (
    <Formik<InfrastructureEditionFormValues>
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
        <Form>
          <AlertConfidenceForEntity entity={infrastructure} />
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <OpenVocabField
            label={t_i18n('Infrastructure types')}
            type="infrastructure_type_ov"
            name="infrastructure_types"
            onSubmit={handleSubmitField}
            onChange={setFieldValue}
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
            onChange={editor.changeField}
            textFieldProps={{
              label: t_i18n('First seen'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
              helperText: (
                <SubscriptionFocus context={context} fieldName="first_seen"/>
              ),
            }}
          />
          <Field
            component={DateTimePickerField}
            name="last_seen"
            onFocus={editor.changeFocus}
            onChange={editor.changeField}
            textFieldProps={{
              label: t_i18n('Last seen'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
              helperText: (
                <SubscriptionFocus context={context} fieldName="last_seen"/>
              ),
            }}
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
              id={infrastructure.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default InfrastructureEditionOverviewComponent;
