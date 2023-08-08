import { ScaleConfig } from '../scale_configuration/scale';

export interface DefaultValue {
  id: string
  name: string
}

export interface AttributeConfiguration {
  name: string
  mandatory?: boolean
  default_values?: string[] | null
  scale?: { local_config: ScaleConfig }
}
