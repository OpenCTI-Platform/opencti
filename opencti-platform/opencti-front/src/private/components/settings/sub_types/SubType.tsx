import { SubTypeQuery } from '@components/settings/sub_types/__generated__/SubTypeQuery.graphql';
import { Box, Stack } from '@mui/material';
import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Outlet, useParams } from 'react-router-dom';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Loader from '../../../../components/Loader';
import TitleMainEntity from '../../../../components/common/typography/TitleMainEntity';
import { useFormatter } from '../../../../components/i18n';
import useAttributes from '../../../../utils/hooks/useAttributes';
import useHelper from '../../../../utils/hooks/useHelper';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import CustomizationMenu from '../CustomizationMenu';
import SubTypeMenu from './SubTypeMenu';
import EntitySettingSettings from './entity_setting/EntitySettingSettings';
import { entitySettingsOverviewLayoutCustomizationFragment } from './entity_setting/EntitySettingsOverviewLayoutCustomization';
import { EntitySettingsOverviewLayoutCustomization_entitySetting$key } from './entity_setting/__generated__/EntitySettingsOverviewLayoutCustomization_entitySetting.graphql';
import { SubTypeTabs } from './SubTypeOutletContext';

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
        ...EntitySettingsFragment_entitySetting
        ...EntitySettingAttributes_entitySetting
        ...FintelTemplatesManager_templates
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
  const { t_i18n } = useFormatter();
  const { typesWithFintelTemplates } = useAttributes();
  const { isFeatureEnable } = useHelper();

  const { subType } = usePreloadedQuery(subTypeQuery, queryRef);

  const entitySetting = useFragment(
    entitySettingsOverviewLayoutCustomizationFragment,
    (subType?.settings ?? null) as EntitySettingsOverviewLayoutCustomization_entitySetting$key,
  );

  if (!subType) return <ErrorNotFound />;

  const subTypeSettingsId = subType.settings?.id;
  if (!subTypeSettingsId) return <ErrorNotFound />;

  const isDraftWorkflowFeatureEnabled = isFeatureEnable('DRAFT_WORKFLOW');
  const isDraftWorkspaceType = subType.label === 'DraftWorkspace' && isDraftWorkflowFeatureEnabled;

  const isWorkflowConfigurationEnabled = !!subType.settings?.availableSettings.includes('workflow_configuration');

  const isFINTELTemplatesEnabled
    = typesWithFintelTemplates.includes(subType.id)
      && !!subType.settings?.availableSettings.includes('templates');

  const isAttributesConfigurationEnabled = !!subType.settings?.availableSettings.includes('attributes_configuration');

  const isCustomOverviewLayoutEnabled = !!entitySetting?.overview_layout_customization;

  const tabs: SubTypeTabs = {
    workflow: isWorkflowConfigurationEnabled,
    attributes: isAttributesConfigurationEnabled,
    templates: isFINTELTemplatesEnabled,
    'overview-layout': isCustomOverviewLayoutEnabled,
  };

  return (
    <Stack sx={{ pr: '200px', pb: 4 }} gap={2}>
      <Breadcrumbs elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Customization') },
        { label: t_i18n('Entity types'), link: '/dashboard/settings/customization/entity_types' },
        { label: t_i18n(`entity_${subType.label}`), current: true },
      ]}
      />

      <TitleMainEntity>
        {t_i18n(`entity_${subType.label}`)}
      </TitleMainEntity>

      {
        !isDraftWorkspaceType && (
          <EntitySettingSettings entitySettingsData={subType.settings} />
        )
      }

      {/** right menu drawer permanent */}
      <CustomizationMenu />

      <SubTypeMenu
        entityType={subType.label}
        isFINTELTemplatesEnabled={isFINTELTemplatesEnabled}
        isAttributesConfigurationEnabled={isAttributesConfigurationEnabled}
        isWorkflowConfigurationEnabled={isWorkflowConfigurationEnabled}
        isCustomOverviewLayoutEnabled={isCustomOverviewLayoutEnabled}
      />

      {/** add a minHeight to prevent page jumps when switching tab
       * that have different content size with magic number */}
      <Box sx={{ minHeight: '240px' }}>
        <Outlet
          context={{
            subType,
            tabs,
          }}
        />
      </Box>

    </Stack>
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
