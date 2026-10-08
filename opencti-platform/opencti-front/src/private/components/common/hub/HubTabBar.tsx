import React from 'react';
import { Link } from 'react-router';
import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';

export interface HubTab {
  /** Route segment, also the tab value. */
  path: string;
  /** English source string, translated here. */
  label: string;
  link: string;
}

interface HubTabBarProps {
  /** Accessible name of the tab list, already translated. */
  label: string;
  /** The open tab, if any. */
  value?: string;
  tabs: HubTab[];
  testIdPrefix: string;
}

/** The tab bar of a hub: one address per tab. */
const HubTabBar = ({ label, value, tabs, testIdPrefix }: HubTabBarProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Tabs value={value} panels="external">
      <TabsList aria-label={label} className="mb-6">
        {tabs.map((tab) => (
          <TabsTrigger key={tab.path} value={tab.path} asChild>
            <Link to={tab.link} data-testid={`${testIdPrefix}-${tab.path}`}>
              {t_i18n(tab.label)}
            </Link>
          </TabsTrigger>
        ))}
      </TabsList>
    </Tabs>
  );
};

export default HubTabBar;
