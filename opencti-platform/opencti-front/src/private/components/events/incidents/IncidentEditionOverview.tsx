import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import inject18n, { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import {
  convertAssignees,
  convertCreatedBy,
  convertMarkings,
  convertStatus, handleChangesObjectAssignee, handleChangesObjectMarking,
} from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';

import {
  IncidentEditionOverviewRelationAddMutation,
} from './__generated__/IncidentEditionOverviewRelationAddMutation.graphql';
import {
  IncidentEditionOverviewRelationDeleteMutation,
} from './__generated__/IncidentEditionOverviewRelationDeleteMutation.graphql';
import {
  IncidentEditionOverviewFieldPatchMutation,
} from './__generated__/IncidentEditionOverviewFieldPatchMutation.graphql';
import { IncidentEditionOverviewFocusMutation } from './__generated__/IncidentEditionOverviewFocusMutation.graphql';
import { Option } from '../../common/form/ReferenceField';
import { IncidentEditionOverview_incident$key } from './__generated__/IncidentEditionOverview_incident.graphql';

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
    $input: StixMetaRelationshipAddInput
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
      description
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
      objectAssignee {
          edges {
              node {
                  id
                  name
                  entity_type
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
      is_inferred
    }
  `;

const IncidentValidation = (t: (v: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  confidence: Yup.number().required(t('This field is required')),
  incident_type: Yup.string(),
  severity: Yup.string(),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
  references: Yup.array().required(t('This field is required')),
});

interface IncidentEditionOverviewProps {
  incidentRef: IncidentEditionOverview_incident$key,
  context: readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[] | null
  enableReferences?: boolean
  handleClose: () => void
}

interface IncidentEditionFormValues {
  message?: string
  references?: Option[]
  createdBy?: Option
  x_opencti_workflow_id: Option
  objectMarking?: Option[]
  objectAssignee?: Option[]
}

const IncidentEditionOverviewComponent : FunctionComponent<IncidentEditionOverviewProps> = ({ incidentRef, context, enableReferences = false, handleClose }) => {
  const { t } = useFormatter();

  const incident = useFragment(incidentEditionOverviewFragment, incidentRef);

  const createdBy = convertCreatedBy(incident);
  const objectMarking = convertMarkings(incident);
  const objectAssignee = convertAssignees(incident);
  const status = convertStatus(t, incident);
  const isInferred = incident.is_inferred;

  const [commitRelationAdd] = useMutation<IncidentEditionOverviewRelationAddMutation>(incidentMutationRelationAdd);
  const [commitRelationDelete] = useMutation<IncidentEditionOverviewRelationDeleteMutation>(incidentMutationRelationDelete);
  const [commitFieldPatch] = useMutation<IncidentEditionOverviewFieldPatchMutation>(incidentMutationFieldPatch);
  const [commitEditionFocus] = useMutation<IncidentEditionOverviewFocusMutation>(incidentEditionOverviewFocus);

  const handleChangeFocus = (name: string) => {
    commitEditionFocus({
      variables: {
        id: incident.id,
        input: {
          focusOn: name,
        },
      },
    });
  };
  const onSubmit: FormikConfig<IncidentEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);

    const inputValues = Object.entries({
      ...otherValues,
      createdBy: values.createdBy?.value,
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));

    commitFieldPatch({
      variables: {
        id: incident.id,
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

  const handleSubmitField = (name: string, value: string | string[] | null) => {
    if (!enableReferences) {
      let finalValue: string = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as unknown as Option).value;
      }
      IncidentValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitFieldPatch({
            variables: {
              id: incident.id,
              input: [{ key: name, value: [finalValue ?? ''] }],
            },
          });
        })
        .catch(() => false);
    }
  };

  const handleChangeObjectMarking = (_: string, values: Option[]) => {
    if (!enableReferences) {
      const { added, removed } = handleChangesObjectMarking(incident, values);
      if (added) {
        commitRelationAdd({
          variables: {
            id: incident.id,
            input: {
              toId: added.value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed) {
        commitRelationDelete({
          variables: {
            id: incident.id,
            toId: removed.value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const handleChangeObjectAssignee = (name: string, values: Option[]) => {
    if (!enableReferences) {
      const { added, removed } = handleChangesObjectAssignee(incident, values);
      if (added) {
        commitRelationAdd({
          variables: {
            id: incident.id,
            input: {
              toId: added.value,
              relationship_type: 'object-assignee',
            },
          },
        });
      }
      if (removed) {
        commitRelationDelete({
          variables: {
            id: incident.id,
            toId: removed.value,
            relationship_type: 'object-assignee',
          },
        });
      }
    }
  };

  const handleChangeCreatedBy = (name: string, value: Option) => {
    if (!enableReferences) {
      commitFieldPatch({
        variables: {
          id: incident.id,
          input: [{ key: 'createdBy', value: [value.value] }],
        },
      });
    }
  };

  const initialValues = {
    name: incident.name,
    description: incident.description,
    incident_type: incident.incident_type,
    severity: incident.severity,
    createdBy,
    objectMarking,
    objectAssignee,
    x_opencti_workflow_id: status,
    status: incident.status,
    workflowEnabled: incident.workflowEnabled,
    is_inferred: isInferred,
    confidence: incident.confidence,
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={IncidentValidation(t)}
      onSubmit={onSubmit}
    >
      {({
        submitForm,
        isSubmitting,
        setFieldValue,
        values,
      }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth={true}
            disabled={isInferred}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <ConfidenceField
            name="confidence"
            onFocus={handleChangeFocus}
            onChange={handleSubmitField}
            label={t('Confidence')}
            disabled={isInferred}
            fullWidth={true}
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <OpenVocabField
            label={t('Incident type')}
            type="incident-type-ov"
            name="incident_type"
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={false}
            editContext={context}
          />
          <OpenVocabField
            label={t('Severity')}
            type="incident-severity-ov"
            name="severity"
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={false}
            editContext={context}
          />
          <Field
            component={MarkDownField}
            name="description"
            label={t('Description')}
            fullWidth={true}
            multiline={true}
            disabled={isInferred}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          <ObjectAssigneeField
            name="objectAssignee"
            style={{ marginTop: 20, width: '100%' }}
            helpertext={
              <SubscriptionFocus
                context={context}
                fieldname="objectAssignee"
              />
            }
            onChange={handleChangeObjectAssignee}
          />
          {incident?.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Incident"
              onFocus={handleChangeFocus}
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
            onChange={handleChangeCreatedBy}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={{ marginTop: 20, width: '100%' }}
            disabled={isInferred}
            helpertext={
              <SubscriptionFocus
                context={context}
                fieldname="objectMarking"
              />
            }
            onChange={handleChangeObjectMarking}
          />
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting}
              open={false}
              setFieldValue={setFieldValue}
              values={values}
              id={incident.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default inject18n(IncidentEditionOverviewComponent);
