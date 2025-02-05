import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import * as Yup from 'yup';
import { GenericContext } from '@components/common/model/GenericContextModel';
import useHelper from 'src/utils/hooks/useHelper';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import { convertAssignees, convertMarkings, convertParticipants, convertStatus } from '../../../../utils/edition';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useDynamicSchemaEditionValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { adaptFieldValue } from '../../../../utils/String';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { Option } from '../../common/form/ReferenceField';
import StatusField from '../../common/form/StatusField';
import { TasksEditionOverview_task$key } from './__generated__/TasksEditionOverview_task.graphql';
import { buildDate, formatDate } from '../../../../utils/Time';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import TaskDeletion from './TaskDeletion';

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
  context?: readonly (GenericContext | null)[] | null;
  enableReferences?: boolean;
  handleClose: () => void;
  tasksPaginationOptions?: { filters: FilterGroup };
}

interface TasksEditionFormValues {
  name: string;
  description: string | null;
  due_date: Date | null;
  message?: string;
  objectMarking?: Option[];
  objectAssignee?: Option[];
  objectParticipant?: Option[]
  x_opencti_workflow_id: Option;
}

const TASK_TYPE = 'Task';

const TasksEditionOverview: FunctionComponent<TasksEditionOverviewProps> = ({
  taskRef,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const taskData = useFragment(tasksEditionOverviewFragment, taskRef);

  const { mandatoryAttributes } = useIsMandatoryAttribute(
    TASK_TYPE,
  );
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    x_opencti_workflow_id: Yup.object().nullable(),
    objectParticipant: Yup.array().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);
  const validator = useDynamicSchemaEditionValidation(mandatoryAttributes, basicShape);

  const queries = {
    fieldPatch: tasksMutationFieldPatch,
    relationAdd: tasksMutationRelationAdd,
    relationDelete: tasksMutationRelationDelete,
    editionFocus: tasksEditionOverviewFocus,
  };
  const editor = useFormEditor(
    taskData as GenericData,
    enableReferences,
    queries,
    validator,
  );

  const onSubmit: FormikConfig<TasksEditionFormValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const { message, ...otherValues } = values;
    const commitMessage = message ?? '';
    const inputValues = Object.entries({
      ...otherValues,
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
    description: taskData.description ?? '',
    due_date: buildDate(taskData.due_date),
    objectMarking: convertMarkings(taskData),
    objectAssignee: convertAssignees(taskData),
    objectParticipant: convertParticipants(taskData),
    x_opencti_workflow_id: convertStatus(t_i18n, taskData) as Option,
  };
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={validator}
      validateOnChange={true}
      validateOnBlur={true}
      onSubmit={onSubmit}
    >
      {({ setFieldValue }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
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
            required={(mandatoryAttributes.includes('due_date'))}
            onFocus={editor.changeFocus}
            onSubmit={editor.changeField}
            textFieldProps={{
              label: t_i18n('Due Date'),
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
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
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
          {isFABReplaced && (
            <TaskDeletion id={taskData.id} />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default TasksEditionOverview;
