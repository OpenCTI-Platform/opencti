import Typography from '@mui/material/Typography';
import React from 'react';
import SubTypeStatusPopover from '@components/settings/sub_types/SubTypeWorkflowPopover';
import { graphql, useFragment } from 'react-relay';
import RequestAccessConfigurationPopover from '@components/settings/sub_types/workflow/RequestAccessConfigurationPopover';
import RequestAccessStatus from '@components/settings/sub_types/workflow/RequestAccessStatus';
import { RequestAccessConfigurationEdition_requestAccess$key } from '@components/settings/sub_types/workflow/__generated__/RequestAccessConfigurationEdition_requestAccess.graphql';
import { useFormatter } from '../../../../../components/i18n';
import { StatusScopeEnum } from '../../../../../utils/statusConstants';
import ItemStatusTemplate from '../../../../../components/ItemStatusTemplate';
import { RequestAccessSettings_requestAccess$key } from './__generated__/RequestAccessSettings_requestAccess.graphql';

const requestAccessSettingsFragment = graphql`
    fragment RequestAccessSettings_requestAccess on SubType {
        statusesRequestAccess {
            id
            order
            scope
            template {
                id
                name
                color
            }
        }
    }
`;

interface RequestAccessSettingsProps {
  subTypeId: string,
  data: RequestAccessSettings_requestAccess$key
  dataConfiguration: RequestAccessConfigurationEdition_requestAccess$key
}

const RequestAccessSettings = ({ subTypeId, data, dataConfiguration }: RequestAccessSettingsProps) => {
  const { t_i18n } = useFormatter();
  const statusesData = useFragment(requestAccessSettingsFragment, data);
  const statusList = statusesData.statusesRequestAccess.map((statusData) => ({
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
      <div style={{ marginTop: 20 }}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Request access workflow')}
          <SubTypeStatusPopover subTypeId={subTypeId} scope={StatusScopeEnum.REQUEST_ACCESS}/>
        </Typography>
        <ItemStatusTemplate
          statuses={statusList}
          disabled={false}
          scope={StatusScopeEnum.REQUEST_ACCESS}
        />
      </div>
      <div style={{ marginTop: 20 }}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Request access action configuration')}
          <RequestAccessConfigurationPopover data={dataConfiguration}/>
          <RequestAccessStatus data={dataConfiguration}/>
        </Typography>
      </div>
    </>
  );
};

export default RequestAccessSettings;
