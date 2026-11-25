import { useMemo } from 'react';
import * as R from 'ramda';
import type { MatrixTechniqueNode } from './buildCellDecorations';
import { getKillChainTechniqueIds, type MatrixPhase, pickDefaultKillChain } from './investigationMatrixUtils';

/**
 * The kill chains of the platform, the one the matrix shows (the user's choice, or the default one while
 * the user has not picked any or picked one the platform no longer has), and that kill chain's techniques.
 */
const useMatrixKillChain = (phases: ReadonlyArray<MatrixPhase>, selectedKillChain: string | undefined) => {
  const killChains = useMemo(
    () => R.uniq(phases.map((phase) => phase.kill_chain_name)).sort((a, b) => a.localeCompare(b)),
    [phases],
  );
  const killChain = selectedKillChain && killChains.includes(selectedKillChain)
    ? selectedKillChain
    : pickDefaultKillChain(killChains);

  const techniqueIds = useMemo(() => getKillChainTechniqueIds(phases, killChain ?? ''), [phases, killChain]);
  const techniques = useMemo(() => {
    const byId = new Map<string, MatrixTechniqueNode>();
    phases
      .filter((phase) => phase.kill_chain_name === killChain)
      .forEach((phase) => (phase.attackPatterns ?? []).forEach((technique) => byId.set(technique.attack_pattern_id, technique)));
    return Array.from(byId.values());
  }, [phases, killChain]);

  return { killChains, killChain, techniqueIds, techniques };
};

export default useMatrixKillChain;
