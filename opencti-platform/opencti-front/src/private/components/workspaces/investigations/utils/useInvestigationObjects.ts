import { useEffect, useRef, useState } from 'react';
import fetchMetaObjectsCount from './fetchMetaObjectsCount';
import { getObjectsToParse } from '../../../../../components/graph/utils/graphUtils';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';

export type InvestigationObjectsData = Parameters<typeof getObjectsToParse>[0];

interface InvestigationObjects {
  objects: ObjectToParse[];
  // Number of loaded objects whose data is in `objects`.
  loadedCount: number;
}

/**
 * Turns the loaded pages of an investigation into graph objects.
 * The loaded count is published together with the matching objects, never before,
 * so a consumer that waits for "loaded" never reads a previous page's objects.
 */
const useInvestigationObjects = (workspace: InvestigationObjectsData | null | undefined): InvestigationObjects => {
  const [published, setPublished] = useState<InvestigationObjects>({ objects: [], loadedCount: 0 });
  const latestRequest = useRef(0);

  useEffect(() => {
    latestRequest.current += 1;
    const request = latestRequest.current;
    const workspaceObjects = workspace ? getObjectsToParse(workspace) : [];
    const loadedCount = workspace?.objects?.edges?.length ?? 0;
    const publish = async () => {
      let objects = workspaceObjects;
      try {
        objects = await fetchMetaObjectsCount(workspaceObjects);
      } catch {
        // Without the relationship counts the objects are still complete: publish them as they are.
      }
      // A newer page started its own lookup: this result is outdated.
      if (request !== latestRequest.current) return;
      setPublished({ objects, loadedCount });
    };
    publish();
  }, [workspace]);

  return published;
};

export default useInvestigationObjects;
