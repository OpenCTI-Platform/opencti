import { Field, FieldProps } from 'formik';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import WorkflowConditionFilters from './WorkflowConditionFilters';
import { WorkflowActionType } from './utils';

interface WorkflowFieldItemProps extends FieldProps {
  isCondition?: boolean;
}

const WorkflowFieldItem = ({ field, isCondition }: WorkflowFieldItemProps) => {
  const { name, value } = field;

  if (isCondition) {
    return <Field name={name} component={WorkflowConditionFilters} />;
  }

  if (value.type === WorkflowActionType.updateAuthorizedMembers) {
    return (
      <Field
        name={`${name}.params.authorized_members`}
        component={AuthorizedMembersField}
        showAllMembersLine
        canDeactivate={false}
        enableAccesses
        hideInfo
        addMeUserWithAdminRights
      />
    );
  }

  if (value.type === WorkflowActionType.shareWithOrganizations || value.type === WorkflowActionType.unshareFromOrganizations) {
    return null;
  }

  return null;
};

export default WorkflowFieldItem;
