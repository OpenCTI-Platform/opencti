import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { SubTypeQuery } from '@components/settings/sub_types/__generated__/SubTypeQuery.graphql';
import { Outlet, useParams } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import CustomizationMenu from '../CustomizationMenu';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import TitleMainEntity from '../../../../components/common/typography/TitleMainEntity';
import SubTypeMenu from './SubTypeMenu';
import useHelper from '../../../../utils/hooks/useHelper';

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
  const { t_i18n } = useFormatter();

  const { subType } = usePreloadedQuery(subTypeQuery, queryRef);
  if (!subType) return <ErrorNotFound />;

  const subTypeSettingsId = subType.settings?.id;
  if (!subTypeSettingsId) return <ErrorNotFound />;

  const { isFeatureEnable } = useHelper();
  const isDraftWorkflowFeatureEnabled = isFeatureEnable('DRAFT_WORKFLOW');
  const isDraftWorkspaceType = subType.label === 'DraftWorkspace' && isDraftWorkflowFeatureEnabled;
  return (
    <div style={{ margin: 0, padding: '0 200px 50px 0' }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Customization') },
        { label: t_i18n('Entity types'), link: '/dashboard/settings/customization/entity_types' },
        { label: t_i18n(`entity_${subType.label}`), current: true },
      ]}
      />

      <CustomizationMenu />

      {isDraftWorkspaceType && (<SubTypeMenu entityType={subType.label} />)}

      <TitleMainEntity sx={{ mb: 3 }}>
        {t_i18n(`entity_${subType.label}`)}
      </TitleMainEntity>

      <Outlet context={{ subType }} />
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
