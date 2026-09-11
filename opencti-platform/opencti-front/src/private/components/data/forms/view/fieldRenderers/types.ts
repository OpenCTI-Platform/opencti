import type React from 'react';
import type { FieldOption } from '../../../../../../utils/field';
import type { FormFieldDefinition } from '../../Form.d';

export interface FieldRendererContext {
  field: FormFieldDefinition;
  values: Record<string, unknown>;
  errors: Record<string, string>;
  touched: Record<string, boolean>;
  setFieldValue: (
    field: string,
    value: string | number | boolean | string[] | Date | null | FieldOption[] | { name?: string; data?: string }[] | {
      label?: string;
      value: string;
      entity?: {
        created: string;
        description?: string | null;
        external_id?: string | null;
        id: string;
        source_name: string;
        url?: string | null;
      };
    }[],
  ) => void;
  entitySettings?: {
    edges: ReadonlyArray<{
      node: {
        id: string;
        target_type: string;
        mandatoryAttributes: ReadonlyArray<string>;
        attributesDefinitions: ReadonlyArray<{
          type: string;
          name: string;
          label?: string | null;
          mandatory: boolean;
        }>;
      };
    }>;
  };
  fieldPrefix?: string;
  useGridLayout?: boolean;
  getNestedValue: (obj: Record<string, unknown>, path: string) => unknown;
}

export type FieldRenderer = (context: FieldRendererContext) => React.ReactNode;
