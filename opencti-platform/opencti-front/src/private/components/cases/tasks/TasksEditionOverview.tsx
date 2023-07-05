import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import * as Yup from 'yup';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import {
  convertAssignees,
  convertCreatedBy,
  convertMarkings, convertParticipants,
  convertStatus,
} from '../../../../utils/edition';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { adaptFieldValue } from '../../../../utils/String';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { Option } from '../../common/form/ReferenceField';
import StatusField from '../../common/form/StatusField';
import { TasksEditionOverview_task$key } from './__generated__/TasksEditionOverview_task.graphql';
import { buildDate, formatDate } from '../../../../utils/Time';
import { TasksFiltering } from './__generated__/TasksRefetch.graphql';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';

export const tasksMutationFieldPatch = graphql`
  mutation TasksEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input, commitMessage: $commitMessage) {
        ...TasksEditionOverview_task
        ...Tasks_tasks
      }
    }
  }
`;

export const tasksEditionOverviewFocus = graphql`
  mutation TasksEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    stixDomainObjectEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const tasksEditionOverviewFragment = graphql`
  fragment TasksEditionOverview_task on Task {
    id
    name
    description
    created
    due_date
    creators {
      id
      name
    }
    x_opencti_stix_ids
    createdBy {
      ... on Identity {
        id
        name
        entity_type
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
    objectParticipant {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
  }
`;

const tasksMutationRelationAdd = graphql`
  mutation TasksEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...TasksEditionOverview_task
        }
      }
    }
  }
`;

const tasksMutationRelationDelete = graphql`
  mutation TasksEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...TasksEditionOverview_task
      }
    }
  }
`;

interface TasksEditionOverviewProps {
  taskRef: TasksEditionOverview_task$key;
  context: ReadonlyArray<{
    readonly focusOn: string | null;
    readonly name: string;
  }> | null;
  enableReferences?: boolean;
  handleClose: () => void;
  tasksPaginationOptions?: { filters: TasksFiltering[] };
}

interface TasksEditionFormValues {
  name: string;
  description: string | null;
  due_date: Date | null;
  message?: string;
  createdBy?: Option;
  objectMarking?: Option[];
  objectAssignee?: Option[];
  objectParticipant?: Option[]
  x_opencti_workflow_id: Option;
}

const TasksEditionOverview: FunctionComponent<TasksEditionOverviewProps> = ({
  taskRef,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t } = useFormatter();
  const taskData = useFragment(tasksEditionOverviewFragment, taskRef);

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    x_opencti_workflow_id: Yup.object().nullable(),
  };
  const taskValidator = useSchemaEditionValidation('Task', basicShape);

  const queries = {
    fieldPatch: tasksMutationFieldPatch,
    relationAdd: tasksMutationRelationAdd,
    relationDelete: tasksMutationRelationDelete,
    editionFocus: tasksEditionOverviewFocus,
  };
  const editor = useFormEditor(
    taskData,
    enableReferences,
    queries,
    taskValidator,
  );

  const onSubmit: FormikConfig<TasksEditionFormValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const { message, ...otherValues } = values;
    const commitMessage = message ?? '';
    const inputValues = Object.entries({
      ...otherValues,
      createdBy: values.createdBy?.value,
      due_date: formatDate(values.due_date),
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
      objectAssignee: (values.objectAssignee ?? []).map(({ value }) => value),
      objectParticipant: (values.objectParticipant ?? []).map(({ value }) => value),
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    editor.fieldPatch({
      variables: {
        id: taskData.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const initialValues: TasksEditionFormValues = {
    name: taskData.name,
    description: taskData.description,
    due_date: buildDate(taskData.due_date),
    createdBy: convertCreatedBy(taskData) as Option,
    objectMarking: convertMarkings(taskData),
    objectAssignee: convertAssignees(taskData),
    objectParticipant: convertParticipants(taskData),
    x_opencti_workflow_id: convertStatus(t, taskData) as Option,
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={taskValidator}
      onSubmit={onSubmit}
    >
      {({ setFieldValue }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={editor.changeField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
            style={{ marginBottom: 10 }}
          />
          <Field
            component={DateTimePickerField}
            name="due_date"
            onFocus={editor.changeFocus}
            onSubmit={editor.changeField}
            TextFieldProps={{
              label: t('Due Date'),
              variant: 'standard',
              fullWidth: true,
              helperText: (
                <SubscriptionFocus context={context} fieldName="due_date" />
              ),
            }}
            containerStyle={fieldSpacingContainerStyle}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
            onFocus={editor.changeFocus}
            onSubmit={editor.changeField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          <ObjectAssigneeField
            name="objectAssignee"
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectAssignee" />
            }
            onChange={editor.changeAssignee}
          />
          <ObjectParticipantField
            name="objectParticipant"
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectParticipant" />
            }
            onChange={editor.changeParticipant}
          />
          {taskData.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Task"
              onFocus={editor.changeFocus}
              onChange={editor.changeField}
              setFieldValue={setFieldValue}
              style={fieldSpacingContainerStyle}
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
            onChange={editor.changeMarking}
          />
        </Form>
      )}
    </Formik>
  );
};

export default TasksEditionOverview;
