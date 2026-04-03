import { Divider, Grid } from '@mui/material';
import { useOutletContext } from 'react-router-dom';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../../components/i18n';
import { SubTypeQuery } from '../__generated__/SubTypeQuery.graphql';
import Card from '@common/card/Card';
import GlobalWorkflowSettings from './GlobalWorkflowSettings';
import RequestAccessSettings from './RequestAccessSettings';

const GlobalWorkflowSettingsCard = () => {
  const { t_i18n } = useFormatter();
  const { subType } = useOutletContext<{ subType: SubTypeQuery['response']['subType'] }>();

  if (!subType) return <ErrorNotFound />;
  if (!subType.settings) return <ErrorNotFound />;

  const hasRequestAccessConfig = subType.settings.availableSettings.includes('request_access_configuration')
    && !!subType.settings.requestAccessConfiguration;

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
        {hasRequestAccessConfig && (
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
              <RequestAccessSettings data={subType} subTypeId={subType.id} dataConfiguration={subType.settings.requestAccessConfiguration} />
            </Grid>
          </>
        )}
      </div>
    </Card>
  );
};

export default GlobalWorkflowSettingsCard;
