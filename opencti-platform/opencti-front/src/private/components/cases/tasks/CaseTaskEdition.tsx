import { Field, Form, Formik } from 'formik';
import React from 'react';
import * as Yup from 'yup';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import TextField from '../../../../components/TextField';
import { convertAssignees, convertMarkings, convertStatus } from '../../../../utils/edition';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { Option } from '../../common/form/ReferenceField';
import StatusField from '../../common/form/StatusField';
import { caseEditionOverviewFocus, caseMutationFieldPatch, caseMutationRelationAdd, caseMutationRelationDelete } from '../CaseUtils';
import { CaseTasksLine_data$data } from './__generated__/CaseTasksLine_data.graphql';

const CaseTaskEdition = ({ task }: { task: CaseTasksLine_data$data }) => {
  const { t } = useFormatter();

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable().max(5000, t('The value is too long')),
    due_date: Yup.date().nullable(),
    objectLabel: Yup.array(),
    objectMarking: Yup.array(),
    objectAssignee: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const taskValidator = useSchemaEditionValidation('Task', basicShape);

  const editor = useFormEditor(
    task,
    false,
    {
      fieldPatch: caseMutationFieldPatch,
      editionFocus: caseEditionOverviewFocus,
      relationAdd: caseMutationRelationAdd,
      relationDelete: caseMutationRelationDelete,
    },
    taskValidator,
  );

  const onSubmit = (name: string, value: Option | Option[] | string) => {
    let finalValue = value;
    if (name === 'x_opencti_workflow_id') {
      finalValue = (value as Option).value;
    }
    taskValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        editor.fieldPatch({
          variables: {
            id: task.id,
            input: [{ key: name, value: Array.isArray(finalValue) ? finalValue.map((o) => o.value) : [finalValue ?? ''] }],
          },
        });
      })
      .catch(() => false);
  };
  return (
    <Formik
      initialValues={{
        ...task,
        objectAssignee: convertAssignees(task),
        objectLabel: (task.objectLabel?.edges ?? []).map(({ node }) => ({ value: node.id, label: node.value })),
        objectMarking: convertMarkings(task),
        x_opencti_workflow_id: convertStatus(t, task) as Option,
      }}
      onSubmit={() => {}}
      validationSchema={taskValidator}
    >
      {({ setFieldValue }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            style={{ marginBottom: 20 }}
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth={true}
            onSubmit={onSubmit}
          />
          <Field
            component={DateTimePickerField}
            name="due_date"
            onSubmit={onSubmit}
            TextFieldProps={{
              label: t('Due Date'),
              variant: 'standard',
              fullWidth: true,
            }}
          />
          <ObjectAssigneeField
            name="objectAssignee"
            style={fieldSpacingContainerStyle}
            onChange={onSubmit}
          />
          <ObjectLabelField
            name="objectLabel"
            style={fieldSpacingContainerStyle}
            onChange={onSubmit}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
            onChange={editor.changeMarking}
          />
          {task.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Task"
              onChange={onSubmit}
              setFieldValue={setFieldValue}
              style={{ marginTop: 20 }}
            />
          )}
          <Field
            component={MarkdownField}
            name="description"
            label={t('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
            onSubmit={onSubmit}
          />
        </Form>
      )}
    </Formik>
  );
};

export default CaseTaskEdition;
