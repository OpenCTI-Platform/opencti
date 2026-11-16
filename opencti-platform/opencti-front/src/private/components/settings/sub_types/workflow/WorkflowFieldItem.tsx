import { useMemo } from 'react';
import { Field, FieldProps } from 'formik';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import ObjectOrganizationField from '@components/common/form/ObjectOrganizationField';
import WorkflowConditionFilters from './WorkflowConditionFilters';
import { REQUEST_ACCESS_AUTHOR_KEY, WorkflowActionType } from './utils';
import { useFormatter } from '../../../../../components/i18n';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';

interface WorkflowFieldItemProps extends FieldProps {
  isCondition?: boolean;
}

const WorkflowFieldItem = ({ field, isCondition }: WorkflowFieldItemProps) => {
  const { name, value } = field;
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const authorLabel = t_i18n('Author (requesting organization)');
  const authorOptions = useMemo(() => [{ value: REQUEST_ACCESS_AUTHOR_KEY, label: authorLabel }], [authorLabel]);

  if (isCondition) {
    return <Field name={name} component={WorkflowConditionFilters} />;
  }

  if (value.type === WorkflowActionType.updateAuthorizedMembers) {
    return (
      <Field
        name={`${name}.params.authorized_members`}
        component={AuthorizedMembersField}
        showAllMembersLine
        withDynamicKeys
        allowDynamicGroupsRestriction
        dynamicContextTypeLabel="Dynamic from draft"
        dynamicAuthorOrgLabel="Draft author (org)"
        dynamicGroupsRestrictionSupportedValues={['AUTHOR']}
        includeBundleOrganizationDynamicOption={false}
        canDeactivate={false}
        enableAccesses
        hideInfo
      />
    );
  }

  if (value.type === WorkflowActionType.shareRequestedEntities) {
    return (
      <ObjectOrganizationField
        name={`${name}.params.organizations`}
        label="Organizations"
        outlined={false}
        multiple
        alert={false}
        style={{ width: '100%' }}
        disabled={!isEnterpriseEdition}
        extraOptions={authorOptions}
        getOptionLabel={(option: { value: string; label: string }) => (option.value === REQUEST_ACCESS_AUTHOR_KEY ? authorLabel : option.label)}
      />
    );
  }

  if (value.type === WorkflowActionType.shareWithOrganizations || value.type === WorkflowActionType.unshareFromOrganizations) {
    return null;
  }

  return null;
};

export default WorkflowFieldItem;
