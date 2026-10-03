import React, { useState } from 'react';
import { useSearchParams } from 'react-router';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import CurationSettings from './CurationSettings';
import CurationPolicies from './CurationPolicies';

export const CURATION_CUSTOMIZATION_TABS = ['settings', 'policies'] as const;
type CurationCustomizationTab = typeof CURATION_CUSTOMIZATION_TABS[number];

const isCurationCustomizationTab = (value: string | null): value is CurationCustomizationTab => {
  return CURATION_CUSTOMIZATION_TABS.includes(value as CurationCustomizationTab);
};

const CurationCustomization = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Curation | Customization | Settings'));
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedTab = searchParams.get('tab');
  const [currentTab, setCurrentTab] = useState<CurationCustomizationTab>(isCurationCustomizationTab(requestedTab) ? requestedTab : 'settings');
  const changeTab = (value: string) => {
    if (!isCurationCustomizationTab(value)) return;
    setCurrentTab(value);
    setSearchParams({ tab: value }, { replace: true });
  };
  return (
    <div data-testid="curation-customization-page">
      <Breadcrumbs
        elements={[
          { label: t_i18n('Settings') },
          { label: t_i18n('Customization') },
          { label: t_i18n('Curation'), current: true },
        ]}
      />
      <Tabs value={currentTab} onValueChange={changeTab}>
        {/* Inline: 200px is the width of the customization menu, and the product compiles no Tailwind. */}
        <div style={{ marginRight: 200 }}>
          <TabsList className="mb-6" aria-label={t_i18n('Curation')}>
            <TabsTrigger value="settings" data-testid="curation-customization-tab-settings">{t_i18n('Settings')}</TabsTrigger>
            <TabsTrigger value="policies" data-testid="curation-customization-tab-policies">{t_i18n('Policies')}</TabsTrigger>
          </TabsList>
        </div>
        <TabsContent value="settings">
          <CurationSettings />
        </TabsContent>
        <TabsContent value="policies">
          <CurationPolicies />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default CurationCustomization;
