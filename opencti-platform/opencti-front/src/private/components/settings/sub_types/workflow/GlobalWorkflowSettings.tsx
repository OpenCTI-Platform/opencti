import SubTypeStatusPopover from '@components/settings/sub_types/SubTypeWorkflowPopover';
import { graphql, useFragment } from 'react-relay';
import ItemStatusTemplate from '../../../../../components/ItemStatusTemplate';
import { StatusScopeEnum } from '../../../../../utils/statusConstants';
import { GlobalWorkflowSettings_global$key } from './__generated__/GlobalWorkflowSettings_global.graphql';

const globalWorkflowSettingsFragment = graphql`
    fragment GlobalWorkflowSettings_global on SubType {
        statuses {
            id
            scope
            order
            template {
                id
                name
                color
            }
        }
    }
`;

interface GlobalWorkflowSettingsProps {
  subTypeId: string;
  workflowEnabled: boolean;
  data: GlobalWorkflowSettings_global$key;
}

const GlobalWorkflowSettings = ({ subTypeId, data, workflowEnabled }: GlobalWorkflowSettingsProps) => {
  const statusesData = useFragment(globalWorkflowSettingsFragment, data);

  const statusList = statusesData.statuses.map((statusData) => ({
    id: statusData.id,
    order: statusData.order,
    template: {
      id: statusData.template?.id ?? '',
      color: statusData.template?.color ?? '#fff',
      name: statusData.template?.name ?? 'unknown',
    },
  }));

  return (
    <ItemStatusTemplate
      statuses={statusList}
      disabled={!workflowEnabled}
      actionComponent={(
        <SubTypeStatusPopover
          subTypeId={subTypeId}
          scope={StatusScopeEnum.GLOBAL}
        />
      )}
    />
  );
};

export default GlobalWorkflowSettings;
