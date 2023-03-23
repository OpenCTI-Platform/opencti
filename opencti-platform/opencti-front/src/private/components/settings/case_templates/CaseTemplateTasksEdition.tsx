import { Field, Form, Formik } from 'formik';
import React from 'react';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { caseEditionOverviewFocus, caseMutationFieldPatch, caseMutationRelationAdd, caseMutationRelationDelete } from '../../cases/CaseUtils';
import { Option } from '../../common/form/ReferenceField';
import { CaseTemplateTasksLine_node$data } from './__generated__/CaseTemplateTasksLine_node.graphql';

const CaseTemplateTasksEdition = ({ task }: { task: CaseTemplateTasksLine_node$data }) => {
  const { t } = useFormatter();

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable().max(5000, t('The value is too long')),
  };
  const taskValidator = useSchemaEditionValidation('Case-Task', basicShape);

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
    taskValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        editor.fieldPatch({
          variables: {
            id: task.id,
            input: [{ key: name, value: Array.isArray(value) ? value.map((o) => o.value) : [value ?? ''] }],
          },
        });
      })
      .catch(() => false);
  };
  return (
    <Formik
      initialValues={task}
      onSubmit={() => {
      }}
      validationSchema={taskValidator}
    >
      {() => (
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
            component={MarkDownField}
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

export default CaseTemplateTasksEdition;
