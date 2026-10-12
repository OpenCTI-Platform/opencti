import React from 'react';
import { Link, Navigate, Route, Routes, useParams } from 'react-router';
import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import CurationSettings from './CurationSettings';
import CurationPolicies from './CurationPolicies';

export const PATH_CURATION_CUSTOMIZATION = '/dashboard/settings/customization/curation';
export const CURATION_CUSTOMIZATION_TABS = ['settings', 'policies'] as const;
type CurationCustomizationTab = typeof CURATION_CUSTOMIZATION_TABS[number];

const isCurationCustomizationTab = (value: string | undefined): value is CurationCustomizationTab => {
  return CURATION_CUSTOMIZATION_TABS.includes(value as CurationCustomizationTab);
};

/**
 * Settings > Customization > Curation. The tab is a route segment (`/curation/settings`, `/curation/policies`), so the
 * lists of a tab can keep their own parameters in the URL.
 */
const CurationCustomizationPage = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Curation | Customization | Settings'));
  const { tab } = useParams();
  if (!isCurationCustomizationTab(tab)) {
    return <Navigate to={`${PATH_CURATION_CUSTOMIZATION}/settings`} replace={true} />;
  }
  return (
    <PageContainer withRightMenu>
      <div data-testid="curation-customization-page">
        <Breadcrumbs
          elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Customization') },
            { label: t_i18n('Curation'), current: true },
          ]}
        />
        <Tabs value={tab} panels="external">
          <TabsList className="mb-6" aria-label={t_i18n('Curation')}>
            <TabsTrigger value="settings" asChild>
              <Link to={`${PATH_CURATION_CUSTOMIZATION}/settings`} data-testid="curation-customization-tab-settings">{t_i18n('Settings')}</Link>
            </TabsTrigger>
            <TabsTrigger value="policies" asChild>
              <Link to={`${PATH_CURATION_CUSTOMIZATION}/policies`} data-testid="curation-customization-tab-policies">{t_i18n('Policies')}</Link>
            </TabsTrigger>
          </TabsList>
        </Tabs>
        {tab === 'settings' ? <CurationSettings /> : <CurationPolicies />}
      </div>
    </PageContainer>
  );
};

const CurationCustomization = () => (
  <Routes>
    <Route path="/" element={<Navigate to={`${PATH_CURATION_CUSTOMIZATION}/settings`} replace={true} />} />
    <Route path="/:tab" element={<CurationCustomizationPage />} />
  </Routes>
);

export default CurationCustomization;
