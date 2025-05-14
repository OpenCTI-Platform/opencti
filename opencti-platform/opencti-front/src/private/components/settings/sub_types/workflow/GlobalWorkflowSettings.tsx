import Typography from '@mui/material/Typography';
import React from 'react';
import SubTypeStatusPopover from '@components/settings/sub_types/SubTypeWorkflowPopover';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../../../components/i18n';
import { StatusScopeEnum } from '../../../../../utils/statusConstants';
import ItemStatusTemplate from '../../../../../components/ItemStatusTemplate';
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
  subTypeId: string,
  workflowEnabled: boolean,
  data: GlobalWorkflowSettings_global$key
}

const GlobalWorkflowSettings = ({ subTypeId, data, workflowEnabled }: GlobalWorkflowSettingsProps) => {
  const { t_i18n } = useFormatter();
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
    <>
      <div>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Global Workflow')}
          <SubTypeStatusPopover subTypeId={subTypeId} scope={StatusScopeEnum.GLOBAL} />
        </Typography>
      </div>
      <ItemStatusTemplate
        statuses={statusList}
        disabled={!workflowEnabled}
      />
    </>
  );
};

export default GlobalWorkflowSettings;
