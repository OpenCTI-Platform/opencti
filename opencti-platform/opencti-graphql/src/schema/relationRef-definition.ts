import type { MandatoryType } from './attribute-definition';

export type Checker = (fromType: string, toType: string) => boolean;

export interface RelationRefDefinition {
  inputName: string
  databaseName: string
  stixName: string
  mandatoryType: MandatoryType
  multiple: boolean
  checker?: Checker // TODO: after migration checker will be mandatory
  label?: string
  description?: string
}
