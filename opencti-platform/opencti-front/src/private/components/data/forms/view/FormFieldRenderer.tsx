import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import { Chip as FdsChip } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { useTheme } from '@mui/styles';
import useAuth from '../../../../../utils/hooks/useAuth';
import { isBypassUser } from '../../../../../utils/hooks/useGranted';
import { fieldRendererRegistry } from './fieldRenderers/registry';
import type { FieldRendererContext, FieldRendererInput } from './fieldRenderers/types';
import './fieldRenderers/primitiveFieldRenderers';
import './fieldRenderers/choiceFieldRenderers';
import './fieldRenderers/dateAndReferenceFieldRenderers';
import './fieldRenderers/fileFieldRenderer';

// Same props a registered field renderer receives via FieldRendererContext, minus the
// getNestedValue/t_i18n helpers this component derives/forwards on their behalf.
export type FormFieldRendererProps = FieldRendererInput;

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

  // Field renderers always build the fully-qualified `fieldPrefix.field.name` path (matching the
  // `name` given to Formik's <Field>) and forward it to composite form components (CreatedByField,
  // ObjectMarkingField, ObjectLabelField, ExternalReferencesField) that call back with that same
  // full name. For additional entities/relationships, the `setFieldValue` this component receives
  // is already a prefixing wrapper expecting a *relative* name (it re-adds the prefix itself), so
  // forwarding it unchanged double-prefixes those callbacks (e.g. `additional_id.additional_id.x`).
  // Normalize here once so every renderer can safely pass the full name regardless of which
  // contract the incoming `setFieldValue` follows.
  const scopedSetFieldValue: FormFieldRendererProps['setFieldValue'] = (name, value) => {
    if (fieldPrefix && name.startsWith(`${fieldPrefix}.`)) {
      setFieldValue(name.slice(fieldPrefix.length + 1), value);
    } else {
      setFieldValue(name, value);
    }
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
      setFieldValue: scopedSetFieldValue,
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
