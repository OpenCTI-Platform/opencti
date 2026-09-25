import type React from 'react';
import type { FieldOption } from '../../../../../../utils/field';
import type { FormFieldDefinition } from '../../Form.d';

// Shared with FormFieldRendererProps (FormFieldRenderer.tsx): both describe the same field-editing
// props the renderer producer collects (from Formik + entity settings) before either rendering the
// field itself or handing it off, wrapped in a FieldRendererContext, to a registered field renderer.
export interface FieldRendererInput {
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
}

export interface FieldRendererContext extends FieldRendererInput {
  getNestedValue: (obj: Record<string, unknown>, path: string) => unknown;
  // Optional so earlier consumers that do not need translation are not forced to supply it; the producer always populates it.
  t_i18n?: (content: string) => string;
}

export type FieldRenderer = (context: FieldRendererContext) => React.ReactNode;
