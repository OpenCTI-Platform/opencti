import React, { useEffect, useState } from 'react';
import Box from '@mui/material/Box';
import { useFormatter } from 'src/components/i18n';
import useConnectedDocumentModifier from 'src/utils/hooks/useConnectedDocumentModifier';
import DecayRules from '@components/settings/decay/DecayRules';
import Breadcrumbs from 'src/components/Breadcrumbs';
import DecayExclusionRules from './DecayExclusionRules';
import KnowledgeDecayRules from './KnowledgeDecayRules';
import { useLocation } from 'react-router';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import useHelper from '../../../../utils/hooks/useHelper';

const DecayRuleTabs = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const location = useLocation();
  const { isProvenanceEnabled } = useHelper();
  const provenanceEnabled = isProvenanceEnabled();
  setTitle(t_i18n('Decay Rules | Customization | Settings'));

  const [currentTab, setCurrentTab] = useState('rules');

  useEffect(() => {
    if (location.state?.decayTab === 'decayExclusionRule') setCurrentTab('exclusions');
    if (location.state?.decayTab === 'knowledgeDecayRule' && provenanceEnabled) setCurrentTab('knowledge');
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
          {/* Inline: 200px is an arbitrary value, and the product compiles no Tailwind. */}
          <div style={{ marginRight: 200 }}>
            <TabsList className="mb-6">
              <TabsTrigger value="rules">{t_i18n('Decay rules')}</TabsTrigger>
              <TabsTrigger value="exclusions">{t_i18n('Decay exclusion rules')}</TabsTrigger>
              {provenanceEnabled && <TabsTrigger value="knowledge">{t_i18n('Knowledge decay rules')}</TabsTrigger>}
            </TabsList>
          </div>

          <TabsContent value="rules">
            <DecayRules />
          </TabsContent>
          {provenanceEnabled && (
            <TabsContent value="knowledge">
              {currentTab === 'knowledge' && <KnowledgeDecayRules />}
            </TabsContent>
          )}
          <TabsContent value="exclusions">
            <DecayExclusionRules />
          </TabsContent>
        </Tabs>
      </Box>
    </>
  );
};

export default DecayRuleTabs;
