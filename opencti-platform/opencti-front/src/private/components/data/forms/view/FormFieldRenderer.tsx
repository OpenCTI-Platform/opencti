import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import { Chip as FdsChip } from '@filigran/design-system';
import { FormFieldDefinition } from '../Form.d';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import type { FieldOption } from '../../../../../utils/field';
import { useTheme } from '@mui/styles';
import useAuth from '../../../../../utils/hooks/useAuth';
import { isBypassUser } from '../../../../../utils/hooks/useGranted';
import { fieldRendererRegistry } from './fieldRenderers/registry';
import type { FieldRendererContext } from './fieldRenderers/types';
import './fieldRenderers/primitiveFieldRenderers';
import './fieldRenderers/choiceFieldRenderers';
import './fieldRenderers/dateAndReferenceFieldRenderers';
import './fieldRenderers/fileFieldRenderer';

export interface FormFieldRendererProps {
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

const FormFieldRenderer: FunctionComponent<FormFieldRendererProps> = ({
  field,
  values,
  errors,
  touched,
  setFieldValue,
  entitySettings,
  fieldPrefix,
  useGridLayout = false,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { me } = useAuth();
  const isBypass = isBypassUser(me);

  // Get the nested value for prefixed fields
  const getNestedValue = (obj: Record<string, unknown>, path: string): unknown => {
    const keys = path.split('.');
    let current: unknown = obj;
    for (const key of keys) {
      if (current && typeof current === 'object' && key in current) {
        current = (current as Record<string, unknown>)[key];
      } else {
        return undefined;
      }
    }
    return current;
  };

  // Calculate grid size based on width configuration
  const getGridSize = () => {
    if (!field.width) return 12; // default to full width
    switch (field.width) {
      case 'full':
        return 12;
      case 'half':
        return 6;
      case 'third':
        return 4;
      default:
        return 12;
    }
  };

  // Render field content based on type
  const renderFieldContent = (): React.ReactNode => {
    const context: FieldRendererContext = {
      field,
      values,
      errors,
      touched,
      setFieldValue,
      entitySettings,
      fieldPrefix,
      useGridLayout,
      getNestedValue,
      t_i18n,
    };
    const renderer = fieldRendererRegistry[field.type] ?? fieldRendererRegistry.default;
    return renderer(context);
  };

  // If grid layout is enabled, wrap in Grid item
  const renderFieldWithGrid = (content: React.ReactNode) => {
    if (useGridLayout) {
      return (
        <Grid item xs={getGridSize()}>
          {content}
        </Grid>
      );
    }
    return content;
  };

  const fieldContent = renderFieldContent();

  if (field.isReadOnly && !isBypass) {
    return null;
  }

  if (field.isReadOnly && isBypass) {
    return renderFieldWithGrid(
      <div style={{ position: 'relative' }}>
        <FdsChip
          severity="high"
          label={t_i18n('Read-Only')}
          style={{ position: 'absolute', top: -10, right: 0, zIndex: 1, backgroundColor: theme.palette.background.paper }}
        />
        {fieldContent}
      </div>,
    );
  }

  return renderFieldWithGrid(fieldContent);
};

export default FormFieldRenderer;
