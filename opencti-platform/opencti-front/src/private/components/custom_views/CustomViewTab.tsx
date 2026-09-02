import { Link } from 'react-router-dom';
import { TabsTrigger } from '@filigran/design-system';
import type { CustomViewDisplayMode } from './useCustomViewTabs';
import { useCustomViews } from './useCustomViews';

type SingleOtherCustomViewTabProps = {
  displayMode: CustomViewDisplayMode;
  otherCustomViews: ReturnType<typeof useCustomViews>['customViews'];
  value: string;
};

/**
 * The "others" custom views as ONE tab. The dropdown variant is authored
 * directly in StixDomainObjectTabsBox: TabsList detects TabsMenuTrigger by
 * displayName, so it cannot be returned from a wrapper like this one.
 */
export const OtherCustomViewsTab = ({ otherCustomViews: customViews, displayMode, value }: SingleOtherCustomViewTabProps) => {
  if (displayMode.others !== 'single') {
    return null;
  }
  return (
    <TabsTrigger value={value} asChild>
      <Link to={customViews[0].path}>{customViews[0].name}</Link>
    </TabsTrigger>
  );
};

type DefaultCustomViewTabProps = {
  value: string;
  displayMode: CustomViewDisplayMode;
  defaultCustomView: ReturnType<typeof useCustomViews>['customViews'][number] | undefined;
};

export const DefaultCustomViewTab = ({ value, displayMode, defaultCustomView }: DefaultCustomViewTabProps) => {
  if (!displayMode.default || !defaultCustomView) {
    return null;
  }
  return (
    <TabsTrigger value={value} asChild>
      <Link to={defaultCustomView.path}>{defaultCustomView.name}</Link>
    </TabsTrigger>
  );
};
