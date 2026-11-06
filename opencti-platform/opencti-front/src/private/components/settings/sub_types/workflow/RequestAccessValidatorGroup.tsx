import { graphql, useFragment } from 'react-relay';
import { Formik } from 'formik';
import GroupField, { GroupFieldOption } from '@components/common/form/GroupField';
import { requestAccessConfigurationFragment } from '../global_workflow_request_access/RequestAccessConfigurationEdition';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { RequestAccessConfigurationEdition_requestAccess$key } from '../global_workflow_request_access/__generated__/RequestAccessConfigurationEdition_requestAccess.graphql';
import { RequestAccessValidatorGroupMutation } from './__generated__/RequestAccessValidatorGroupMutation.graphql';

const requestAccessValidatorGroupMutation = graphql`
  mutation RequestAccessValidatorGroupMutation($input: RequestAccessConfigureInput!) {
    requestAccessConfigure(input: $input) {
      id
      approval_admin {
        id
        name
      }
    }
  }
`;

interface ValidatorGroupFormValues {
  approvalAdmin: GroupFieldOption | null;
}

// Only the validator group is sent: the configuration keeps its statuses and its workflow definition.
const RequestAccessValidatorGroup = () => {
  const { t_i18n } = useFormatter();
  const { subType } = useSubTypeOutletContext();
  const configuration = useFragment(
    requestAccessConfigurationFragment,
    subType.settings.requestAccessConfiguration as RequestAccessConfigurationEdition_requestAccess$key | null | undefined,
  );
  const [commit] = useApiMutation<RequestAccessValidatorGroupMutation>(
    requestAccessValidatorGroupMutation,
    undefined,
    { successMessage: t_i18n('Request access configuration successfully updated') },
  );

  const validator = configuration?.approval_admin?.[0];
  const initialValues: ValidatorGroupFormValues = {
    approvalAdmin: validator ? { label: validator.name, value: validator.id } : null,
  };

  const handleChange = (_name: string, value: GroupFieldOption | null) => {
    commit({ variables: { input: { approval_admin: value ? [value.value] : [] } } });
  };

  return (
    <Formik<ValidatorGroupFormValues>
      enableReinitialize={true}
      initialValues={initialValues}
      onSubmit={() => {}}
    >
      <GroupField
        name="approvalAdmin"
        label={t_i18n('Validator group membership:')}
        onChange={handleChange}
        multiple={false}
        style={{ width: 280 }}
      />
    </Formik>
  );
};

export default RequestAccessValidatorGroup;
