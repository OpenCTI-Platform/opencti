import React, { useEffect, useState } from 'react';
import Box from '@mui/material/Box';
import { useFormatter } from 'src/components/i18n';
import useConnectedDocumentModifier from 'src/utils/hooks/useConnectedDocumentModifier';
import DecayRules from '@components/settings/decay/DecayRules';
import Breadcrumbs from 'src/components/Breadcrumbs';
import DecayExclusionRules from './DecayExclusionRules';
import { useLocation } from 'react-router-dom';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';

const DecayRuleTabs = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const location = useLocation();
  setTitle(t_i18n('Decay Rules | Customization | Settings'));

  const [currentTab, setCurrentTab] = useState('rules');

  useEffect(() => {
    if (location.state?.decayTab === 'decayExclusionRule') setCurrentTab('exclusions');
  }, []);

  return (
    <>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Settings') },
          { label: t_i18n('Customization') },
          { label: t_i18n('Decay rules'), current: true },
        ]}
      />
      <Box>
        <Tabs value={currentTab} onValueChange={setCurrentTab}>
          {/* The right nav is a fixed 200px drawer floating over the content;
              both panels already reserve that gutter, the strip did not. */}
          <TabsList className="mb-6 mr-[200px]">
            <TabsTrigger value="rules">{t_i18n('Decay rules')}</TabsTrigger>
            <TabsTrigger value="exclusions">{t_i18n('Decay exclusion rules')}</TabsTrigger>
          </TabsList>

          <TabsContent value="rules">
            <DecayRules />
          </TabsContent>
          <TabsContent value="exclusions">
            <DecayExclusionRules />
          </TabsContent>
        </Tabs>
      </Box>
    </>
  );
};

export default DecayRuleTabs;
