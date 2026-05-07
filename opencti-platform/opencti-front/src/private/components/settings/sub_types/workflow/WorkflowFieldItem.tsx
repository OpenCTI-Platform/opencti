import { Field, FieldProps } from 'formik';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import { TextField as MuiTextField, Typography } from '@mui/material';
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

  if (value.type === WorkflowActionType.asyncBulkAction) {
    return (
      <div>
        <Typography variant="caption" color="text.secondary">
          Scope: {value.params?.scope ?? 'KNOWLEDGE'}
        </Typography>
        {value.params?.description && (
          <MuiTextField
            size="small"
            fullWidth
            label="Description"
            value={value.params.description ?? ''}
            InputProps={{ readOnly: true }}
            sx={{ mt: 1 }}
          />
        )}
      </div>
    );
  }

  return null;
};

export default WorkflowFieldItem;
