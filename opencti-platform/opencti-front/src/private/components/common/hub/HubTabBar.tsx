import React from 'react';
import { Link } from 'react-router';
import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import HubCountBadge, { type HubBadgeCount } from './HubCountBadge';

export interface HubTab {
  /** Route segment, also the tab value. */
  path: string;
  /** English source string, translated here. */
  label: string;
  link: string;
  useBadgeCount?: HubBadgeCount;
}

interface HubTabBarProps {
  /** Accessible name of the tab list, already translated. */
  label: string;
  /** The open tab, if any. */
  value?: string;
  tabs: HubTab[];
  testIdPrefix: string;
}

/** The tab bar of a hub: one address per tab, and the pending count of each tab next to its label. */
const HubTabBar = ({ label, value, tabs, testIdPrefix }: HubTabBarProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Tabs value={value} panels="external">
      <TabsList aria-label={label} className="mb-6">
        {tabs.map((tab) => (
          <TabsTrigger key={tab.path} value={tab.path} asChild>
            <Link to={tab.link} data-testid={`${testIdPrefix}-${tab.path}`}>
              <span className="inline-flex items-center gap-2">
                {t_i18n(tab.label)}
                {tab.useBadgeCount && <HubCountBadge useCount={tab.useBadgeCount} />}
              </span>
            </Link>
          </TabsTrigger>
        ))}
      </TabsList>
    </Tabs>
  );
};

export default HubTabBar;
