export const fieldSpacingContainerStyle = { marginTop: 20, width: '100%' };

export interface FieldOption {
  id?: string;
  value: string;
  label: string;
  color?: string;
  type?: string;
  standard_id?: string;
}

// TODO move this interface inside file KillChainPhasesField
// when it has been transformed it TypeScript.
export interface KillChainPhaseFieldOption extends FieldOption {
  kill_chain_name: string;
  phase_name: string;
}
