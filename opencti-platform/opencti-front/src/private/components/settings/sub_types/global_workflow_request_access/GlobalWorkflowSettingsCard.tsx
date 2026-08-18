import Card from '@common/card/Card';
import { Divider, Grid, Tooltip } from '@mui/material';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import Switch from '@mui/material/Switch';
import { graphql } from 'react-relay';
import { InformationOutline } from 'mdi-material-ui';
import Label from '../../../../../components/common/label/Label';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import GlobalWorkflowSettings from './GlobalWorkflowSettings';
import RequestAccessSettings from './RequestAccessSettings';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import useHelper from '../../../../../utils/hooks/useHelper';

const globalWorkflowSettingsCardPatch = graphql`
    mutation GlobalWorkflowSettingsCardPatchMutation(
        $ids: [ID!]!
        $input: [EditInput!]!
    ) {
        entitySettingsFieldPatch(ids: $ids, input: $input) {
            id
            sync_workflow_status_by_name
        }
    }
`;

const GlobalWorkflowSettingsCard = () => {
  const { t_i18n } = useFormatter();

  const { subType } = useSubTypeOutletContext();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { isFeatureEnable } = useHelper();
  const isSyncWorkflowStatusByNameFeatureEnabled = isFeatureEnable('SYNC_WORKFLOW_STATUS_BY_NAME');
  const requestAccessConfiguration = subType.settings.requestAccessConfiguration;
  const [commit] = useApiMutation(globalWorkflowSettingsCardPatch);

  const hasRequestAccessConfig = isEnterpriseEdition
    && subType.settings.availableSettings.includes('request_access_workflow')
    && !!requestAccessConfiguration;

  const isSyncWorkflowStatusByNameAvailable = subType.settings.availableSettings.includes('sync_workflow_status_by_name');

  const handleToggleSyncWorkflowStatusByName = () => {
    commit({
      variables: {
        ids: [subType.settings.id],
        input: { key: 'sync_workflow_status_by_name', value: (!subType.settings.sync_workflow_status_by_name).toString() },
      },
    });
  };

  return (
    <Card title={t_i18n('Workflow')}>
      <div style={{ display: 'flex' }}>
        <Grid item xs={hasRequestAccessConfig ? 6 : 12}>
          {subType.settings?.availableSettings.includes('workflow_configuration')
            && (
              <GlobalWorkflowSettings data={subType} subTypeId={subType.id} workflowEnabled={subType.workflowEnabled ?? false} />
            )
          }
          {isSyncWorkflowStatusByNameFeatureEnabled && (
            <>
              <Label action={(
                <Tooltip
                  title={!isSyncWorkflowStatusByNameAvailable
                    ? t_i18n('This configuration is not available for this entity type')
                    : t_i18n("When enabled, stream synchronizations will try to name-match the incoming entities' statuses with this instance's statuses, instead of dropping them.")
                  }
                >
                  <InformationOutline
                    fontSize="small"
                    color="primary"
                  />
                </Tooltip>
              )}
              >
                {t_i18n('Sync workflow statuses by name')}
              </Label>
              <FormGroup>
                <FormControlLabel
                  control={(
                    <Switch
                      disabled={!isSyncWorkflowStatusByNameAvailable}
                      checked={subType.settings.sync_workflow_status_by_name ?? false}
                      onChange={handleToggleSyncWorkflowStatusByName}
                    />
                  )}
                  label={t_i18n('Sync workflow statuses by name')}
                />
              </FormGroup>
            </>
          )}
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
