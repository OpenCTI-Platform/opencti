import { useOutletContext } from 'react-router-dom';
import { SubTypeQuery } from './__generated__/SubTypeQuery.graphql';

export type SubTypeTabs = Record<'workflow' | 'attributes' | 'templates' | 'overview-layout' | 'custom-views', boolean>;

type ResolvedSubType = NonNullable<SubTypeQuery['response']['subType']> & {
  settings: NonNullable<NonNullable<SubTypeQuery['response']['subType']>['settings']>;
};

type ResolvedCustomViews = NonNullable<SubTypeQuery['response']['customViewsSettings']>;

export interface SubTypeOutletContext {
  subType: ResolvedSubType;
  tabs: SubTypeTabs;
  customViewsSettings: ResolvedCustomViews;
}

export const useSubTypeOutletContext = (): SubTypeOutletContext => {
  const { subType, tabs, customViewsSettings } = useOutletContext<SubTypeOutletContext>();

  if (!subType?.settings) throw new Error('SubType or its settings are missing from outlet context');

  return { subType, tabs, customViewsSettings };
};
