import { useOutletContext } from 'react-router-dom';
import { SubTypeQuery } from './__generated__/SubTypeQuery.graphql';

export type SubTypeTabs = Record<'workflow' | 'attributes' | 'templates' | 'overview-layout', boolean>;

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
