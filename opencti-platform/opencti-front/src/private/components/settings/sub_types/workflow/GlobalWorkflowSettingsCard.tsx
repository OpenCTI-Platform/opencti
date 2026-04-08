import Card from '@common/card/Card';
import { Divider, Grid } from '@mui/material';
import { useFormatter } from '../../../../../components/i18n';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import GlobalWorkflowSettings from './GlobalWorkflowSettings';
import RequestAccessSettings from './RequestAccessSettings';

const GlobalWorkflowSettingsCard = () => {
  const { t_i18n } = useFormatter();

  const { subType } = useSubTypeOutletContext();
  const requestAccessConfiguration = subType.settings.requestAccessConfiguration;

  const hasRequestAccessConfig = subType.settings.availableSettings.includes('request_access_configuration')
    && !!requestAccessConfiguration;

  return (
    <Card title={t_i18n('Workflow')}>
      <div style={{ display: 'flex' }}>
        <Grid item xs={hasRequestAccessConfig ? 6 : 12}>
          {subType.settings?.availableSettings.includes('workflow_configuration')
            && (
              <GlobalWorkflowSettings data={subType} subTypeId={subType.id} workflowEnabled={subType.workflowEnabled ?? false} />
            )
          }
        </Grid>
        {hasRequestAccessConfig && requestAccessConfiguration && (
          <>
            <Grid item>
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
            <Grid item xs={6}>
              <RequestAccessSettings data={subType} subTypeId={subType.id} dataConfiguration={requestAccessConfiguration} />
            </Grid>
          </>
        )}
      </div>
    </Card>
  );
};

export default GlobalWorkflowSettingsCard;
