import { SubTypeQuery, SubTypeQuery$variables } from '@components/settings/sub_types/__generated__/SubTypeQuery.graphql';
import EntitySettingCustomOverview from '@components/settings/sub_types/entity_setting/EntitySettingCustomOverview';
import GlobalWorkflowSettings from '@components/settings/sub_types/workflow/GlobalWorkflowSettings';
import RequestAccessSettings from '@components/settings/sub_types/workflow/RequestAccessSettings';
import Divider from '@mui/material/Divider';
import Grid from '@mui/material/Grid';
import { useMemo } from 'react';
import { graphql, useSubscription } from 'react-relay';
import { useOutletContext } from 'react-router-dom';
import Card from '../../../../components/common/card/Card';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useHelper from '../../../../utils/hooks/useHelper';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import EntitySettingAttributes from './entity_setting/EntitySettingAttributes';
import EntitySettingSettings from './entity_setting/EntitySettingSettings';
import FintelTemplatesGrid from './fintel_templates/FintelTemplatesGrid';

const entitySettingSubscription = graphql`
  subscription SubTypeOverviewEntitySettingSubscription($id: ID!) {
    entitySetting(id: $id) {
      ...EntitySettingSettings_entitySetting
    }
  }
`;

const SubTypeOverview = () => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();

  const { subType } = useOutletContext<{ subType: SubTypeQuery['response']['subType'] }>();
  if (!subType) return <ErrorNotFound />;

  const subTypeSettingsId = subType.settings?.id;
  if (!subTypeSettingsId) return <ErrorNotFound />;

  const config = useMemo(
    () => ({
      subscription: entitySettingSubscription,
      variables: { id: subTypeSettingsId },
    }),
    [subType.settings],
  );
  useSubscription(config);

  const LOCAL_STORAGE_KEY = `${subType.id}-attributes`;
  const { viewStorage, helpers } = usePaginationLocalStorage<SubTypeQuery$variables>(
    LOCAL_STORAGE_KEY,
    { searchTerm: '' },
  );
  const { searchTerm } = viewStorage;

  const hasTemplates = subType.settings?.availableSettings.includes('templates');

  const hasRequestAccessConfig = subType.settings?.requestAccessConfiguration && isEnterpriseEdition && subType.settings?.availableSettings.includes('request_access_workflow');

  const { isFeatureEnable } = useHelper();
  const isDraftWorkflowFeatureEnabled = isFeatureEnable('DRAFT_WORKFLOW');
  const isDraftWorkspaceType = subType.label === 'DraftWorkspace' && isDraftWorkflowFeatureEnabled;

  return (
    <Grid container spacing={3}>
      {!isDraftWorkspaceType && (
        <Grid item xs={hasTemplates ? 6 : 12}>
          <Card title={t_i18n('Configuration')}>
            <EntitySettingSettings entitySettingsData={subType.settings} />
          </Card>
        </Grid>
      )}

      {hasTemplates && <FintelTemplatesGrid data={subType.settings} />}

      {!isDraftWorkspaceType && (
        <Grid item xs={12}>
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
        </Grid>
      )}

      {subType.settings?.availableSettings.includes('attributes_configuration') && (
        <Grid item xs={12}>
          <Card
            title={t_i18n('Attributes')}
            titleSx={{ alignItems: 'end' }}
            sx={{ paddingTop: 0, paddingBottom: 0 }}
            action={(
              <SearchInput
                variant="thin"
                onSubmit={helpers.handleSearch}
                keyword={searchTerm}
              />
            )}
          >
            <EntitySettingAttributes
              entitySettingsData={subType.settings}
              searchTerm={searchTerm}
            />
          </Card>
        </Grid>
      )}

      <EntitySettingCustomOverview
        entitySettingsData={subType.settings}
      />
    </Grid>
  );
};

export default SubTypeOverview;
