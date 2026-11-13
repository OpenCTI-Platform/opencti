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
