export interface PlaybookUpdateAction {
  op?: string
  attribute?: string
  formValue?: unknown
  value?: {
    label?: string
    value?: string
    patch_value?: string | {
      kill_chain_name: string,
      phase_name: string
    }
  }[]
}

export interface PlaybookUpdateActionsForm {
  actions: PlaybookUpdateAction[]
}
