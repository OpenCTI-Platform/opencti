import { useOutletContext } from 'react-router-dom';
import { SubTypeQuery } from './__generated__/SubTypeQuery.graphql';

export const SUBTYPE_TAB_WORKFLOW = 'workflow';
export const SUBTYPE_TAB_ATTRIBUTES = 'attributes';
export const SUBTYPE_TAB_TEMPLATES = 'templates';
export const SUBTYPE_TAB_OVERVIEW_LAYOUT = 'overview-layout';
export const SUBTYPE_TAB_CUSTOM_VIEWS = 'custom-views';

// List of tabs ordered as they are displayed in the UI
export const SUBTYPE_TABS = [
  SUBTYPE_TAB_WORKFLOW,
  SUBTYPE_TAB_ATTRIBUTES,
  SUBTYPE_TAB_TEMPLATES,
  SUBTYPE_TAB_OVERVIEW_LAYOUT,
  SUBTYPE_TAB_CUSTOM_VIEWS,
] as const;

export type SubTypeTabs = Record<typeof SUBTYPE_TABS[number], boolean>;

type ResolvedSubType = NonNullable<SubTypeQuery['response']['subType']> & {
  settings: NonNullable<NonNullable<SubTypeQuery['response']['subType']>['settings']>;
};

export interface SubTypeOutletContext {
  subType: ResolvedSubType;
  tabs: SubTypeTabs;
}

export const useSubTypeOutletContext = (): SubTypeOutletContext => {
  const { subType, tabs } = useOutletContext<SubTypeOutletContext>();

  if (!subType?.settings) throw new Error('SubType or its settings are missing from outlet context');

  return { subType, tabs };
};
