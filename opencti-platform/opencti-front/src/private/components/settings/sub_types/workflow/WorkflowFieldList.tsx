import { Typography, IconButton } from '@mui/material';
import { Add } from '@mui/icons-material';
import { FieldArray, Field, useFormikContext } from 'formik';
import ActionMenuButton from './ActionMenuButton';
import WorkflowFieldItem from './WorkflowFieldItem';
import { WorkflowDataType } from './utils';
import type { WorkflowEditionFormValues } from './WorkflowEditionDrawer';
import type { Action } from './utils';

interface WorkflowFieldListProps {
  title: string;
  name: keyof typeof WorkflowDataType;
  isActionMenu?: boolean;
}

const WorkflowFieldList = ({ title, name, isActionMenu }: WorkflowFieldListProps) => {
  const { values, setFieldValue, status: { onAddObject } } = useFormikContext<WorkflowEditionFormValues>();

  const isConditions = name === 'conditions';

  return (
    <div style={{ marginBottom: '20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: '10px' }}>
        <Typography variant="h3" sx={{ m: 0 }}>{title}</Typography>
        {isActionMenu ? (
          <ActionMenuButton onAddObject={onAddObject} type={name} />
        ) : (
          <IconButton color="secondary" onClick={() => onAddObject(WorkflowDataType.conditions, name, setFieldValue, values)}>
            <Add fontSize="small" />
          </IconButton>
        )}
      </div>
      <FieldArray name={name}>
        {(arrayHelpers) => {
          if (isConditions) {
            return (
              <Field key={name} name={name} component={WorkflowFieldItem} onDelete={() => arrayHelpers.remove(0)} />
            );
          }
          return (values[name] as Action[])?.map((_, idx: number) => (
            <Field
              key={`${name}-${idx}`}
              component={WorkflowFieldItem}
              name={`${name}[${idx}]`}
              onDelete={() => arrayHelpers.remove(idx)}
            />
          ));
        }}
      </FieldArray>
    </div>
  );
};

export default WorkflowFieldList;
