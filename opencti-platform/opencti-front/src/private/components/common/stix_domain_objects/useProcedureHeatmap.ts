import { useRef, useState } from 'react';
import { buildProcedureUsage } from '../../techniques/attack_patterns/attack_patterns_matrix/procedureHeatmap';
import type { TechniqueUsage } from '../../workspaces/investigations/matrix/matrixTypes';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { buildProcedureHeatmapFilters, toProceduresWithTechniques } from './StixDomainObjectAttackPatternsProcedureHeatmap';
import type { StixDomainObjectAttackPatternsProcedureHeatmapQuery$data } from './__generated__/StixDomainObjectAttackPatternsProcedureHeatmapQuery.graphql';

interface UseProcedureHeatmapArgs {
  entityId: string;
  load: (variables: { filters: FilterGroup }) => Promise<StixDomainObjectAttackPatternsProcedureHeatmapQuery$data>;
  onError: (error: unknown) => void;
}

// Procedure heatmap state: loads the procedures the entity uses only when turned on. Clicks while a load is in
// flight are ignored, so a double click cannot leave the heatmap in the state the user did not ask for.
const useProcedureHeatmap = ({ entityId, load, onError }: UseProcedureHeatmapArgs) => {
  const [procedureUsage, setProcedureUsage] = useState<Map<string, TechniqueUsage> | undefined>();
  const [isLoading, setIsLoading] = useState(false);
  const loading = useRef(false);

  const toggle = async () => {
    if (loading.current) return;
    if (procedureUsage) {
      setProcedureUsage(undefined);
      return;
    }
    loading.current = true;
    setIsLoading(true);
    try {
      const data = await load({ filters: buildProcedureHeatmapFilters(entityId) });
      setProcedureUsage(buildProcedureUsage(toProceduresWithTechniques(data)));
    } catch (error) {
      onError(error);
    } finally {
      loading.current = false;
      setIsLoading(false);
    }
  };

  return { procedureUsage, isLoading, toggle };
};

export default useProcedureHeatmap;
