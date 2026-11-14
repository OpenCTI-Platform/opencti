import { useCallback, useState } from 'react';
import type { EntityOption } from '@components/common/form/EntitySelect';

/**
 * What the user chose in the matrix toolbar. The matrix unmounts when the graph view is shown,
 * so these settings are held by the investigation graph, which stays mounted, and survive a view switch.
 */
export interface InvestigationMatrixSettings {
  // Undefined until the user picks one: the matrix then shows the default kill chain.
  killChain?: string;
  onlyUsed: boolean;
  heatmap: boolean;
  securityPlatforms: EntityOption[];
}

export type InvestigationMatrixSettingsChange = (change: Partial<InvestigationMatrixSettings>) => void;

export const DEFAULT_INVESTIGATION_MATRIX_SETTINGS: InvestigationMatrixSettings = {
  killChain: undefined,
  onlyUsed: false,
  heatmap: false,
  securityPlatforms: [],
};

/**
 * The matrix settings of one investigation. The graph component is reused when the user opens another
 * investigation: that one starts from the defaults instead of inheriting the previous kill chain, heatmap
 * or security platforms.
 */
export const useInvestigationMatrixSettings = (
  investigationId: string,
): [InvestigationMatrixSettings, InvestigationMatrixSettingsChange] => {
  const [state, setState] = useState({ investigationId, settings: DEFAULT_INVESTIGATION_MATRIX_SETTINGS });
  const settings = state.investigationId === investigationId ? state.settings : DEFAULT_INVESTIGATION_MATRIX_SETTINGS;
  const change = useCallback<InvestigationMatrixSettingsChange>((update) => setState((current) => ({
    investigationId,
    settings: { ...(current.investigationId === investigationId ? current.settings : DEFAULT_INVESTIGATION_MATRIX_SETTINGS), ...update },
  })), [investigationId]);
  return [settings, change];
};
