import React, { useEffect, useState } from 'react';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useFormatter } from 'src/components/i18n';
import useConnectedDocumentModifier from 'src/utils/hooks/useConnectedDocumentModifier';
import DecayRules from '@components/settings/decay/DecayRules';
import Breadcrumbs from 'src/components/Breadcrumbs';
import CustomizationMenu from '@components/settings/CustomizationMenu';
import DecayExclusionRules from './DecayExclusionRules';
import { useLocation } from 'react-router-dom';

const DecayRuleTabs = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const location = useLocation();
  setTitle(t_i18n('Decay Rules | Customization | Settings'));

  const [currentTab, setCurrentTab] = useState<number>(0);

  useEffect(() => {
    if (location.state?.decayTab === 'decayExclusionRule') setCurrentTab(1);
  }, []);

  const handleChangeTab = (_: React.SyntheticEvent, value: number) => setCurrentTab(value);

  return (
    <>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Settings') },
          { label: t_i18n('Customization') },
          { label: t_i18n('Decay rules'), current: true },
        ]}
      />
      <CustomizationMenu />
      <Box>
        <Tabs
          value={currentTab}
          onChange={handleChangeTab}
          style={{ marginBottom: '20px' }}
        >
          <Tab label={t_i18n('Decay rules')} />
          <Tab label={t_i18n('Decay exclusion rules')} />
        </Tabs>
        {currentTab === 0 && <DecayRules />}
        {currentTab === 1 && <DecayExclusionRules />}
      </Box>
    </>
  );
};

export default DecayRuleTabs;
