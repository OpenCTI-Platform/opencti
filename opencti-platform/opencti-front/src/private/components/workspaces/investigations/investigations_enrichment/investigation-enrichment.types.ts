import { InvestigationEnrichmentToolQuery$data } from './__generated__/InvestigationEnrichmentToolQuery.graphql';

export type Investigation = NonNullable<InvestigationEnrichmentToolQuery$data['workspace']>;
export type InvestigationEnrichmentWork = NonNullable<NonNullable<NonNullable<Investigation['enrichmentWorks']>['edges']>[0]>['node'];
