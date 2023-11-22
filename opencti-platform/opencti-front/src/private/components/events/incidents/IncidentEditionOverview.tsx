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
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertAssignees, convertCreatedBy, convertMarkings, convertParticipants, convertStatus } from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import { Option } from '../../common/form/ReferenceField';
import { IncidentEditionOverview_incident$key } from './__generated__/IncidentEditionOverview_incident.graphql';
import { useSchemaEditionValidation, useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import { GenericContext } from '../../common/model/GenericContextModel';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const incidentMutationFieldPatch = graphql`
  mutation IncidentEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    incidentEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...IncidentEditionOverview_incident
        ...Incident_incident
      }
    }
  }
`;

export const incidentEditionOverviewFocus = graphql`
  mutation IncidentEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    incidentEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const incidentMutationRelationAdd = graphql`
  mutation IncidentEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    incidentEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...IncidentEditionOverview_incident
        }
      }
    }
  }
`;

const incidentMutationRelationDelete = graphql`
  mutation IncidentEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    incidentEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...IncidentEditionOverview_incident
      }
    }
  }
`;

const incidentEditionOverviewFragment = graphql`
  fragment IncidentEditionOverview_incident on Incident {
    id
    name
    confidence
    entity_type
    description
    source
    incident_type
    severity
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
    objectAssignee {
      id
      name
      entity_type
    }
    objectParticipant {
      id
      name
      entity_type
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
    is_inferred
  }
`;

interface IncidentEditionOverviewProps {
  incidentRef: IncidentEditionOverview_incident$key;
  context?: readonly (GenericContext | null)[] | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface IncidentEditionFormValues {
  message?: string;
  references?: Option[];
  createdBy: Option | undefined;
  x_opencti_workflow_id: Option;
  objectMarking?: Option[];
  objectAssignee?: Option[];
  objectParticipant?: Option[];

}

const INCIDENT_TYPE = 'Incident';

const IncidentEditionOverviewComponent: FunctionComponent<
IncidentEditionOverviewProps
> = ({ incidentRef, context, enableReferences = false, handleClose }) => {
  const { t_i18n } = useFormatter();
  const incident = useFragment(incidentEditionOverviewFragment, incidentRef);
  const { mandatoryAttributes } = useIsMandatoryAttribute(
    INCIDENT_TYPE,
  );
  const basicShape = {
    name: Yup.string().trim().min(2),
    incident_type: Yup.string().nullable(),
    severity: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    description: Yup.string().nullable(),
    x_opencti_workflow_id: Yup.object(),
    references: Yup.array(),
  };
  const incidentValidator = useSchemaEditionValidation(INCIDENT_TYPE, basicShape);
  const queries = {
    fieldPatch: incidentMutationFieldPatch,
    relationAdd: incidentMutationRelationAdd,
    relationDelete: incidentMutationRelationDelete,
    editionFocus: incidentEditionOverviewFocus,
  };
  const editor = useFormEditor(
    incident as GenericData,
    enableReferences,
    queries,
    incidentValidator,
  );
  const onSubmit: FormikConfig<IncidentEditionFormValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);
    const inputValues = Object.entries({
      ...otherValues,
      createdBy: values.createdBy?.value,
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
      objectAssignee: (values.objectAssignee ?? []).map(({ value }) => value),
      objectParticipant: (values.objectParticipant ?? []).map(({ value }) => value),
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    editor.fieldPatch({
      variables: {
        id: incident.id,
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
  const handleSubmitField = (name: string, value: string | string[] | number | number[] | null) => {
    if (!enableReferences) {
      let finalValue: string = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as unknown as Option).value;
      }
      incidentValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: incident.id,
              input: [{ key: name, value: [finalValue ?? ''] }],
            },
          });
        })
        .catch(() => false);
    }
  };
  const isInferred = incident.is_inferred;
  const initialValues = {
    name: incident.name,
    description: incident.description,
    incident_type: incident.incident_type,
    severity: incident.severity,
    createdBy: convertCreatedBy(incident) as Option,
    objectMarking: convertMarkings(incident),
    objectAssignee: convertAssignees(incident),
    objectParticipant: convertParticipants(incident),
    x_opencti_workflow_id: convertStatus(t_i18n, incident) as Option,
    confidence: incident.confidence,
    references: [],
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={incidentValidator}
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
          <AlertConfidenceForEntity entity={incident} />
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            disabled={isInferred}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Incident"
            disabled={isInferred}
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <OpenVocabField
            label={t_i18n('Incident type')}
            type="incident-type-ov"
            name="incident_type"
            required={(mandatoryAttributes.includes('incident_type'))}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={false}
            editContext={context}
          />
          <OpenVocabField
            label={t_i18n('Severity')}
            type="incident-severity-ov"
            name="severity"
            required={(mandatoryAttributes.includes('severity'))}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={false}
            editContext={context}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
            fullWidth={true}
            multiline={true}
            disabled={isInferred}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          <ObjectAssigneeField
            name="objectAssignee"
            required={(mandatoryAttributes.includes('objectAssignee'))}
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectAssignee" />
            }
            onChange={editor.changeAssignee}
          />
          <ObjectParticipantField
            name="objectParticipant"
            required={(mandatoryAttributes.includes('objectParticipant'))}
            style={fieldSpacingContainerStyle}
            onChange={editor.changeParticipant}
          />
          {incident?.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Incident"
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
            disabled={isInferred}
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
              open={false}
              values={values.references}
              setFieldValue={setFieldValue}
              id={incident.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default IncidentEditionOverviewComponent;
