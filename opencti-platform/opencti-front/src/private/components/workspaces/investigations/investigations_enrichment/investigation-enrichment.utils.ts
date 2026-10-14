import { InvestigationEnrichmentWork } from './investigation-enrichment.types';

export const addInEnrichmentMap = (
  map: Map<string, InvestigationEnrichmentWork[]>,
  work?: InvestigationEnrichmentWork,
) => {
  if (work && work.event_source_id) {
    if (map.has(work.event_source_id)) {
      map.get(work.event_source_id)?.push(work);
    } else {
      map.set(work.event_source_id, [work]);
    }
  }
};
