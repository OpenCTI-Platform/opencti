import Typography from '@mui/material/Typography';
import React, { CSSProperties, Suspense, useMemo } from 'react';
import Paper from '@mui/material/Paper';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import Grid from '@mui/material/Grid';
import EntitySettingCustomOverview from '@components/settings/sub_types/entity_setting/EntitySettingCustomOverview';
import { useTheme } from '@mui/styles';
import { SubTypeQuery, SubTypeQuery$variables } from '@components/settings/sub_types/__generated__/SubTypeQuery.graphql';
import { useParams } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import ItemStatusTemplate from '../../../../components/ItemStatusTemplate';
import SubTypeStatusPopover from './SubTypeWorkflowPopover';
import EntitySettingSettings from './entity_setting/EntitySettingSettings';
import EntitySettingAttributes from './entity_setting/EntitySettingAttributes';
import CustomizationMenu from '../CustomizationMenu';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import type { Theme } from '../../../../components/Theme';
import FintelTemplatesGrid from './fintel_templates/FintelTemplatesGrid';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import useHelper from '../../../../utils/hooks/useHelper';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';

const entitySettingSubscription = graphql`
  subscription SubTypeEntitySettingSubscription($id: ID!) {
    entitySetting(id: $id) {
      ...EntitySettingSettings_entitySetting
    }
  }
`;

export const subTypeQuery = graphql`
  query SubTypeQuery($id: String!) {
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
      }
      statuses {
        id
        order
        template {
          name
          color
        }
      }
    }
  }
`;

interface SubTypeProps {
  queryRef: PreloadedQuery<SubTypeQuery>
}

const SubTypeComponent: React.FC<SubTypeProps> = ({ queryRef }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFileFromTemplateEnabled = isFeatureEnable('FILE_FROM_TEMPLATE');

  const { subType } = usePreloadedQuery(subTypeQuery, queryRef);
  if (!subType) return <ErrorNotFound/>;

  const subTypeSettingsId = subType.settings?.id;
  if (!subTypeSettingsId) return <ErrorNotFound/>;

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

  const hasTemplates = subType.settings?.availableSettings.includes('templates') && isFileFromTemplateEnabled

  const paperStyle: CSSProperties = {
    marginTop: theme.spacing(1),
    padding: theme.spacing(2),
    borderRadius: theme.spacing(0.5),
    position: 'relative',
  };

  return (
    <div style={{ margin: 0, padding: '0 200px 50px 0' }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Customization') },
        { label: t_i18n('Entity types'), link: '/dashboard/settings/customization/entity_types' },
        { label: subType.label },
      ]}
      />

      <CustomizationMenu />

      <Typography variant="h1" gutterBottom={true} sx={{ mb: 3 }}>
        {t_i18n(`entity_${subType.label}`)}
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={hasTemplates ? 6 : 12}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Configuration')}
          </Typography>
          <Paper
            style={paperStyle}
            variant="outlined"
            className={'paper-for-grid'}
          >
            <EntitySettingSettings entitySettingsData={subType.settings} />
            {subType.settings?.availableSettings.includes('workflow_configuration')
              && <>
                <div style={{ marginTop: 10 }}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Workflow')}
                    <SubTypeStatusPopover subTypeId={subType.id} />
                  </Typography>
                </div>
                <ItemStatusTemplate
                  statuses={subType.statuses}
                  disabled={!subType.workflowEnabled}
                />
              </>
            }
          </Paper>
        </Grid>

        {hasTemplates && <FintelTemplatesGrid data={subType.settings} />}

        {subType.settings?.availableSettings.includes('attributes_configuration') && (
          <Grid item xs={12}>
            <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
              {t_i18n('Attributes')}
            </Typography>
            <div style={{ float: 'right', marginTop: -12 }}>
              <SearchInput
                variant="thin"
                onSubmit={helpers.handleSearch}
                keyword={searchTerm}
              />
            </div>
            <div className="clearfix" />
            <Paper
              style={paperStyle}
              variant="outlined"
              className={'paper-for-grid'}
            >
              <EntitySettingAttributes
                entitySettingsData={subType.settings}
                searchTerm={searchTerm}
              ></EntitySettingAttributes>
            </Paper>
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
  if (!subTypeId) return <ErrorNotFound/>;

  const subTypeRef = useQueryLoading<SubTypeQuery>(subTypeQuery, { id: subTypeId });

  return (
    <Suspense fallback={<Loader />}>
      {subTypeRef && <SubTypeComponent queryRef={subTypeRef} />}
    </Suspense>
  );
};

export default SubType;
