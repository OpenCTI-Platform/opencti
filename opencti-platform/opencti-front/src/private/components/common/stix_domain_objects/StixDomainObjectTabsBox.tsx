import type { PropsWithChildren, ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { MenuItem, Tabs, TabsList, TabsMenuTrigger, TabsTrigger } from '@filigran/design-system';
import { getCurrentTab } from '../../../../utils/tabUtils';
import { useFormatter } from '../../../../components/i18n';
import useCustomViewTabs from '@components/custom_views/useCustomViewTabs';
import { OtherCustomViewsTab, DefaultCustomViewTab } from '@components/custom_views/CustomViewTab';
import { CUSTOM_VIEW_TAB_VALUE, DEFAULT_CUSTOM_VIEW_TAB_VALUE } from '@components/custom_views/useCustomViews';

export type StixDomainObjectTabsBoxTab
  = | 'overview'
    | 'result'
    | 'knowledge'
    | 'content'
    | 'analyses'
    | 'sightings'
    | 'entities'
    | 'observables'
    | 'files'
    | 'history';

interface StixDomainObjectTabsBoxProps {
  basePath: string;
  entityType: string;
  tabs: StixDomainObjectTabsBoxTab[];
  extraActions?: ReactNode;
}

interface TabInfo {
  /** Tab identifier **/
  tab: StixDomainObjectTabsBoxTab;
  /** Relative path to navigate to **/
  path: string;
  /** Label key **/
  label: string;
}

// Information about static tabs.
// Order is important, will be reflected in the UI.
const TABS_INFO: readonly TabInfo[] = [{
  tab: 'overview',
  path: 'overview',
  label: 'Overview',
}, {
  tab: 'result',
  path: 'result',
  label: 'Result',
}, {
  tab: 'knowledge',
  path: 'knowledge',
  label: 'Knowledge',
}, {
  tab: 'content',
  path: 'content',
  label: 'Content',
}, {
  tab: 'analyses',
  path: 'analyses',
  label: 'Analyses',
}, {
  tab: 'sightings',
  path: 'sightings',
  label: 'Sightings',
}, {
  tab: 'entities',
  path: 'entities',
  label: 'Entities',
}, {
  tab: 'observables',
  path: 'observables',
  label: 'Observables',
}, {
  tab: 'files',
  path: 'files',
  label: 'Data',
}, {
  tab: 'history',
  path: 'history',
  label: 'History',
}];

type TabsWithCustomViewsProps = PropsWithChildren<{
  basePath: string;
  entityType: string;
  currentTab: string;
  extraActions?: ReactNode;
}>;

const TabsWithCustomViews = ({
  children,
  basePath,
  entityType,
  currentTab,
  extraActions,
}: TabsWithCustomViewsProps) => {
  const { t_i18n } = useFormatter();
  const {
    defaultCustomView,
    otherCustomViews,
    displayMode,
    currentCustomViewTab,
    currentCustomViewMenuItem,
  } = useCustomViewTabs({ basePath, entityType });

  return (
    <Tabs value={(currentCustomViewTab ?? currentTab) || ''} panels="external">
      <TabsList actions={extraActions}>
        <DefaultCustomViewTab
          value={DEFAULT_CUSTOM_VIEW_TAB_VALUE}
          displayMode={displayMode}
          defaultCustomView={defaultCustomView}
        />
        {children}
        <OtherCustomViewsTab
          value={CUSTOM_VIEW_TAB_VALUE}
          displayMode={displayMode}
          otherCustomViews={otherCustomViews}
        />
        {/* Authored here, not in a wrapper: TabsList lifts TabsMenuTrigger out
            of the tablist by displayName, which a wrapper would hide. */}
        {displayMode.others === 'dropdown' && (
          <TabsMenuTrigger
            active={currentCustomViewTab === CUSTOM_VIEW_TAB_VALUE}
            menu={otherCustomViews.map(({ id, name, path }) => (
              <MenuItem key={id} selected={currentCustomViewMenuItem === path} asChild>
                <Link to={path}>{name}</Link>
              </MenuItem>
            ))}
          >
            {t_i18n('Custom view')}
          </TabsMenuTrigger>
        )}
      </TabsList>
    </Tabs>
  );
};

/**
 * Tabs container shared across all SDO pages.
 * Applies common logic to display (or not) the "Custom views" tab.
 */
const StixDomainObjectTabsBox = (props: StixDomainObjectTabsBoxProps) => {
  const { basePath, entityType, extraActions, tabs } = props;
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const currentTab = getCurrentTab(location.pathname, basePath);

  const staticTabs = TABS_INFO.map(({ tab, path, label }) =>
    tabs.includes(tab) && (
      <TabsTrigger key={tab} value={path} asChild>
        <Link to={path}>{t_i18n(label)}</Link>
      </TabsTrigger>
    ));

  return (
    <TabsWithCustomViews
      basePath={basePath}
      entityType={entityType}
      currentTab={currentTab}
      extraActions={extraActions}
    >
      {staticTabs}
    </TabsWithCustomViews>
  );
};

export default StixDomainObjectTabsBox;
