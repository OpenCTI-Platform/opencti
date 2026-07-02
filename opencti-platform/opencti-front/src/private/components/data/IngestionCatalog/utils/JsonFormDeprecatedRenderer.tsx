import React, { useEffect, useRef } from 'react';
import { and, ControlProps, isControl, rankWith, RankedTester, schemaMatches } from '@jsonforms/core';
import { JsonFormsDispatch, withJsonFormsControlProps } from '@jsonforms/react';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { lighten, useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import Tag from '../../../../../components/common/tag/Tag';

const formatDeprecatedDescription = (rawDescription?: string) => {
  if (!rawDescription) {
    return rawDescription;
  }

  return rawDescription.replace(/\b[A-Z0-9]+(?:_[A-Z0-9]+)+\b/g, (token) => token.replace(/_/g, ' '));
};

export const JsonFormDeprecatedRenderer = (props: ControlProps) => {
  const {
    uischema,
    schema,
    path,
    enabled,
    visible,
    renderers,
    cells,
    label,
    description,
    data,
    handleChange,
  } = props;

  const rootSchema = (props as ControlProps & { rootSchema?: Record<string, unknown> }).rootSchema;

  const { t_i18n } = useFormatter();
  const theme = useTheme() as Theme;
  const formattedDescription = formatDeprecatedDescription(description);

  // color is computed to ensure sufficient contrast with the background in both light and dark mode,
  // while still being visually associated with the warning status
  const warningBaseColor = theme.palette.designSystem.alert.warning.primary ?? '#E6700F';
  const warningHintColor = theme.palette.mode === 'light'
    ? lighten(warningBaseColor, 0.18)
    : lighten(warningBaseColor, 0.72);

  if (!visible) {
    return null;
  }

  const schemaWithoutDeprecated = {
    ...schema,
    deprecated: false,
  };

  const uischemaWithoutLabel = {
    ...uischema,
    label: false,
  };

  const nestedRenderers = renderers?.filter((entry) => entry.tester !== jsonFormDeprecatedTester);

  const parentPath = path.includes('.') ? path.substring(0, path.lastIndexOf('.')) : '';
  const hasInitializedValue = useRef(false);

  useEffect(() => {
    if (hasInitializedValue.current) {
      return;
    }

    if (data === undefined && schema.default !== undefined) {
      handleChange(path, schema.default);
      hasInitializedValue.current = true;
      return;
    }

    if (data !== undefined) {
      hasInitializedValue.current = true;
    }
  }, [data, schema.default, handleChange, path]);

  return (
    <Box sx={{ mb: 2 }}>
      <Stack direction="row" alignItems="center" spacing={1}>
        <Typography component="label" variant="subtitle2" sx={{ fontSize: '11px' }}>
          {label}
        </Typography>
        <Tag
          tooltipTitle={formattedDescription}
          sx={{ color: warningHintColor }}
          label={t_i18n('Deprecated')}
          color={theme.palette.designSystem.tertiary.orange[400] ?? '#F2933A'}
        />
      </Stack>

      <JsonFormsDispatch
        uischema={uischemaWithoutLabel}
        schema={rootSchema ?? schemaWithoutDeprecated}
        path={parentPath}
        enabled={enabled}
        renderers={nestedRenderers ?? renderers}
        cells={cells}
      />

      <Typography
        variant="caption"
        sx={{ color: warningHintColor }}
      >
        {t_i18n('This field is deprecated. It is shown because a value was previously set. Consider removing it if no longer needed.')}
      </Typography>
    </Box>
  );
};

export const jsonFormDeprecatedTester: RankedTester = rankWith(
  20,
  and(
    isControl,
    schemaMatches((schema) => (schema as Record<string, unknown>)['deprecated'] === true),
  ),
);

export default withJsonFormsControlProps(JsonFormDeprecatedRenderer);
