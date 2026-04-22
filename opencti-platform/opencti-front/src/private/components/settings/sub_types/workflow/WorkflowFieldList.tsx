import { Typography } from '@mui/material';
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
  const { values, status: { onAddObject } } = useFormikContext<WorkflowEditionFormValues>();

  if (!isActionMenu) {
    return (
      <div style={{ marginBottom: '20px' }}>
        <Field
          key={name}
          name={name}
          component={WorkflowFieldItem}
        />
      </div>
    );
  }

  return (
    <div style={{ marginBottom: '20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: '10px' }}>
        <Typography variant="h3" sx={{ m: 0 }}>{title}</Typography>
        <ActionMenuButton onAddObject={onAddObject} type={name} />
      </div>
      <FieldArray name={name}>
        {(arrayHelpers) => (values[name] as Action[])?.map((_, idx: number) => (
          <Field
            key={`${name}-${idx}`}
            component={WorkflowFieldItem}
            name={`${name}[${idx}]`}
            onDelete={() => arrayHelpers.remove(idx)}
          />
        ))}
      </FieldArray>
    </div>
  );
};

export default WorkflowFieldList;
