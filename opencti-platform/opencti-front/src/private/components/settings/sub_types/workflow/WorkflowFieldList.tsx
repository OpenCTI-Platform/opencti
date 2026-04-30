import { Field, useFormikContext } from 'formik';
import WorkflowFieldItem from './WorkflowFieldItem';
import { WorkflowDataType } from './utils';
import type { WorkflowEditionFormValues } from './WorkflowEditionDrawer';

interface WorkflowFieldListProps {
  name: keyof typeof WorkflowDataType;
}

const WorkflowFieldList = ({ name }: WorkflowFieldListProps) => {
  const { values } = useFormikContext<WorkflowEditionFormValues>();
  const items = values[name];
  const isCondition = name === 'conditions';

  const content = () => {
    if (isCondition && items) {
      return (
        <Field
          name={name}
          component={WorkflowFieldItem}
          isCondition={isCondition}
        />
      );
    }
    if (Array.isArray(items)) {
      return items.map((_, idx: number) => (
        <Field
          key={`${name}-${idx}`}
          name={`${name}[${idx}]`}
          component={WorkflowFieldItem}
          isCondition={isCondition}
        />
      ));
    }
    return null;
  };

  return <div>{content()}</div>;
};

export default WorkflowFieldList;
