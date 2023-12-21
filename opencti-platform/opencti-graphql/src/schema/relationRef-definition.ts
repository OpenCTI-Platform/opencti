import type { MandatoryType } from './attribute-definition';

export type Checker = (fromType: string, toType: string) => boolean;

export interface RelationRefDefinition {
  inputName: string
  databaseName: string
  stixName: string
  mandatoryType: MandatoryType
  editDefault: boolean
  multiple: boolean
  checker: Checker
  label: string
  description?: string
  datable?: boolean // Allow to update start_time & stop_time attributes
  isFilterable: boolean
}
