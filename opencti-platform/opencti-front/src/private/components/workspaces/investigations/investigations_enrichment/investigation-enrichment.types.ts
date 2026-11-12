import { InvestigationEnrichmentToolQuery$data } from './__generated__/InvestigationEnrichmentToolQuery.graphql';
import { TabList } from './InvestigationEnrichmentDrawerTabs';

export type Investigation = NonNullable<InvestigationEnrichmentToolQuery$data['workspace']>;
export type InvestigationEnrichmentWork = NonNullable<NonNullable<NonNullable<Investigation['enrichmentWorks']>['edges']>[0]>['node'];

export type InvestigationWorkSorted = Record<TabList, Map<string, InvestigationEnrichmentWork[]>>;
