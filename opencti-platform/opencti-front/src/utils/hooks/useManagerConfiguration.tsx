import { graphql, loadQuery, usePreloadedQuery } from 'react-relay';
import { environment } from '../../relay/environment';
import { FILE_INDEX_MANAGER } from '../platformModulesHelper';
import { useManagerConfigurationQuery } from './__generated__/useManagerConfigurationQuery.graphql';

const managerConfigurationQuery = graphql`
  query useManagerConfigurationQuery($managerId: String!) {
    managerConfigurationByManagerId(managerId: $managerId) {
      id
      manager_id
      manager_running
      last_run_start_date
      last_run_end_date
    }
  }
`;

const queryRef = loadQuery<useManagerConfigurationQuery>(
  environment,
  managerConfigurationQuery,
  { managerId: FILE_INDEX_MANAGER },
);

const useManagerConfiguration = () => {
  const data = usePreloadedQuery<useManagerConfigurationQuery>(
    managerConfigurationQuery,
    queryRef,
  );

  return data.managerConfigurationByManagerId;
};

export default useManagerConfiguration;
