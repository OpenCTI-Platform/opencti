import { Node } from "reactflow";
import { PlaybookFlow_playbookComponents$data } from "../playbookFlow/__generated__/PlaybookFlow_playbookComponents.graphql";
import { PlaybookUpdateAction } from "../playbookFlow/playbookFlowFields/playbookFlowFieldsActions/playbookAction-types";

export type PlaybookComponents = NonNullable<PlaybookFlow_playbookComponents$data['playbookComponents']>;
export type PlaybookComponent = NonNullable<PlaybookComponents[number]>;

export interface PlaybookConfig {
  filters?: string
  actions?: PlaybookUpdateAction[]
  triggerTime?: string
}

export type PlaybookNode = Node<{
  name?: string
  configuration?: PlaybookConfig
  component?: PlaybookComponent
}>

export type PlaybookComponentConfigSchema = {
  type: string
  required: string[]
  properties: {
    [key in keyof PlaybookConfig]: {
      type: string
      uniqueItems?: boolean
      $ref?: string
      default?: PlaybookConfig[key]
      oneOf?: unknown[]
      items?: {
        type: string
        oneOf?: unknown[]
        properties: {
          op?: {
            type: string
            enum: string[]
          }
        }
      }
    }
  }
}