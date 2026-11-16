import Card from '@common/card/Card';
import { Divider, Grid } from '@mui/material';
import { useFormatter } from '../../../../../components/i18n';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import GlobalWorkflowSettings from './GlobalWorkflowSettings';
import RequestAccessSettings from './RequestAccessSettings';
import EntityStatusSyncSetting from './EntityStatusSyncSetting';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';

const GlobalWorkflowSettingsCard = () => {
  const { t_i18n } = useFormatter();

  const { subType } = useSubTypeOutletContext();
  const isEnterpriseEdition = useEnterpriseEdition();
  const requestAccessConfiguration = subType.settings.requestAccessConfiguration;

  const hasRequestAccessConfig = isEnterpriseEdition
    && subType.settings.availableSettings.includes('request_access_workflow')
    && !!requestAccessConfiguration;

  return (
    <Card title={t_i18n('Workflow')}>
      <Grid container wrap="nowrap">
        <Grid size={hasRequestAccessConfig ? 6 : 12}>
          {subType.settings?.availableSettings.includes('workflow_configuration')
            && (
              <GlobalWorkflowSettings data={subType} subTypeId={subType.id} workflowEnabled={subType.workflowEnabled ?? false} />
            )
          }
          <EntityStatusSyncSetting sx={{ marginTop: 4 }} />
        </Grid>
        {hasRequestAccessConfig && requestAccessConfiguration && (
          <>
            <Grid>
              <Divider
                orientation="vertical"
                style={{
                  display: 'inline-block',
                  verticalAlign: 'middle',
                  height: '100%',
                  margin: '0 20px',
                }}
              />
            </Grid>
            <Grid size={6}>
              <RequestAccessSettings data={subType} subTypeId={subType.id} dataConfiguration={requestAccessConfiguration} />
            </Grid>
          </>
        )}
      </Grid>
    </Card>
  );
};

export default GlobalWorkflowSettingsCard;
