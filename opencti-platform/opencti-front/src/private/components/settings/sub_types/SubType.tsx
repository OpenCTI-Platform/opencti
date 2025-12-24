import Typography from '@mui/material/Typography';
import React, { Suspense, useMemo } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import Grid from '@mui/material/Grid';
import EntitySettingCustomOverview from '@components/settings/sub_types/entity_setting/EntitySettingCustomOverview';
import { useTheme } from '@mui/styles';
import { SubTypeQuery, SubTypeQuery$variables } from '@components/settings/sub_types/__generated__/SubTypeQuery.graphql';
import { useParams } from 'react-router-dom';
import GlobalWorkflowSettings from '@components/settings/sub_types/workflow/GlobalWorkflowSettings';
import RequestAccessSettings from '@components/settings/sub_types/workflow/RequestAccessSettings';
import Divider from '@mui/material/Divider';
import { useFormatter } from '../../../../components/i18n';
import EntitySettingSettings from './entity_setting/EntitySettingSettings';
import EntitySettingAttributes from './entity_setting/EntitySettingAttributes';
import CustomizationMenu from '../CustomizationMenu';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import type { Theme } from '../../../../components/Theme';
import FintelTemplatesGrid from './fintel_templates/FintelTemplatesGrid';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import Card from '../../../../components/common/card/Card';

const entitySettingSubscription = graphql`
  subscription SubTypeEntitySettingSubscription($id: ID!) {
    entitySetting(id: $id) {
      ...EntitySettingSettings_entitySetting
    }
  }
`;

export const subTypeQuery = graphql`
  query SubTypeQuery($id: String!){
    subType(id: $id) {
      id
      label
      workflowEnabled
      settings {
        id
        availableSettings
        ...EntitySettingsOverviewLayoutCustomization_entitySetting
        ...EntitySettingSettings_entitySetting
        ...EntitySettingAttributes_entitySetting
        ...FintelTemplatesGrid_templates
        requestAccessConfiguration{
            ...RequestAccessStatusFragment_requestAccess
            ...RequestAccessConfigurationEdition_requestAccess
        }
      }
      ...GlobalWorkflowSettings_global
      ...RequestAccessSettings_requestAccess
    }
  }
`;

interface SubTypeProps {
  queryRef: PreloadedQuery<SubTypeQuery>;
}

const SubTypeComponent: React.FC<SubTypeProps> = ({ queryRef }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();

  const { subType } = usePreloadedQuery(subTypeQuery, queryRef);
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

  return (
    <div style={{ margin: 0, padding: '0 200px 50px 0' }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Customization') },
        { label: t_i18n('Entity types'), link: '/dashboard/settings/customization/entity_types' },
        { label: t_i18n(`entity_${subType.label}`) },
      ]}
      />

      <CustomizationMenu />

      <Typography variant="h1" gutterBottom={true} sx={{ mb: 3 }}>
        {t_i18n(`entity_${subType.label}`)}
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={hasTemplates ? 6 : 12}>
          <Card title={t_i18n('Configuration')}>
            <EntitySettingSettings entitySettingsData={subType.settings} />
          </Card>
        </Grid>

        {hasTemplates && <FintelTemplatesGrid data={subType.settings} />}

        <Grid item xs={12}>
          <Card title={t_i18n('Workflow')}>
            <div style={{ display: 'flex', marginTop: theme.spacing(1) }}>
              <Grid item xs={hasRequestAccessConfig ? 6 : 12}>
                {subType.settings?.availableSettings.includes('workflow_configuration')
                  && <GlobalWorkflowSettings data={subType} subTypeId={subType.id} workflowEnabled={subType.workflowEnabled ?? false} />
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

        {subType.settings?.availableSettings.includes('attributes_configuration') && (
          <Grid item xs={12}>
            <Card
              title={t_i18n('Attributes')}
              titleSx={{ alignItems: 'end' }}
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
    </div>
  );
};

const SubType = () => {
  const { subTypeId } = useParams<{ subTypeId?: string }>();
  if (!subTypeId) return <ErrorNotFound />;

  const subTypeRef = useQueryLoading<SubTypeQuery>(subTypeQuery, { id: subTypeId });

  return (
    <Suspense fallback={<Loader />}>
      {subTypeRef && <SubTypeComponent queryRef={subTypeRef} />}
    </Suspense>
  );
};

export default SubType;
