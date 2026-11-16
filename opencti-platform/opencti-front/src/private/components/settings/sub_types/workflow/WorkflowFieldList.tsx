import { Field, useFormikContext } from 'formik';
import WorkflowFieldItem from './WorkflowFieldItem';
import { WorkflowActionType, WorkflowDataType } from './utils';
import type { WorkflowEditionFormValues } from './WorkflowEditionDrawer';

interface WorkflowFieldListProps {
  name: keyof typeof WorkflowDataType;
  // Renders only the actions of this type; every action of the list otherwise.
  actionType?: WorkflowActionType;
}

const WorkflowFieldList = ({ name, actionType }: WorkflowFieldListProps) => {
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
      return items.map((item, idx: number) => (
        !actionType || item.type === actionType ? (
          <Field
            key={`${name}-${idx}`}
            name={`${name}[${idx}]`}
            component={WorkflowFieldItem}
            isCondition={isCondition}
          />
        ) : null
      ));
    }
    return null;
  };

  return <div>{content()}</div>;
};

export default WorkflowFieldList;
