import Typography from '@mui/material/Typography';
import React, { CSSProperties } from 'react';
import SubTypeStatusPopover from '@components/settings/sub_types/SubTypeWorkflowPopover';
import { graphql, useFragment } from 'react-relay';
import RequestAccessConfigurationPopover from '@components/settings/sub_types/workflow/RequestAccessConfigurationPopover';
import RequestAccessStatus from '@components/settings/sub_types/workflow/RequestAccessStatus';
import { RequestAccessConfigurationEdition_requestAccess$key } from '@components/settings/sub_types/workflow/__generated__/RequestAccessConfigurationEdition_requestAccess.graphql';
import Paper from '@mui/material/Paper';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../../components/i18n';
import { StatusScopeEnum } from '../../../../../utils/statusConstants';
import ItemStatusTemplate from '../../../../../components/ItemStatusTemplate';
import { RequestAccessSettings_requestAccess$key } from './__generated__/RequestAccessSettings_requestAccess.graphql';
import type { Theme } from '../../../../../components/Theme';

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
  const theme = useTheme<Theme>();

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

  const paperStyle: CSSProperties = {
    marginTop: theme.spacing(1),
    padding: theme.spacing(2),
    borderRadius: theme.spacing(0.5),
    position: 'relative',
  };
  return (
    <>
      <div>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Specific Workflow for Request Access')}
          <SubTypeStatusPopover subTypeId={subTypeId} scope={StatusScopeEnum.REQUEST_ACCESS}/>
        </Typography>
        <ItemStatusTemplate
          statuses={statusList}
          disabled={false}
        />
      </div>
      <div style={{ marginTop: 20 }}>
        <Paper
          style={paperStyle}
          variant="outlined"
          className={'paper-for-grid'}
        >
          <Typography variant="h3" gutterBottom={true}>
            {t_i18n('Request access actions configuration')}
            <RequestAccessConfigurationPopover data={dataConfiguration}/>
            <RequestAccessStatus data={dataConfiguration}/>
          </Typography>
        </Paper>
      </div>
    </>
  );
};

export default RequestAccessSettings;
