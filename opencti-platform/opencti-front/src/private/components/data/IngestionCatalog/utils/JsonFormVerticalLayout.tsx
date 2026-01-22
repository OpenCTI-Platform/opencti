import { Layout, LayoutProps, rankWith, uiTypeIs } from '@jsonforms/core';
import { JsonFormsDispatch, withJsonFormsLayoutProps } from '@jsonforms/react';
import { Box } from '@mui/material';
import React from 'react';

const VerticalLayoutWithSpacingRenderer = (props: LayoutProps) => {
  const layout = props.uischema as Layout;
  const { renderers, cells, schema, path, enabled, visible } = props;

  if (!visible) {
    return null;
  }

  return (
    layout.elements.map((child, index) => (
      <Box key={index} sx={{ marginTop: index === 0 ? 0 : '20px' }}>
        <JsonFormsDispatch
          uischema={child}
          schema={schema}
          path={path}
          enabled={enabled}
          renderers={renderers}
          cells={cells}
        />
      </Box>
    ))
  );
};

export const JsonFormVerticalLayout = withJsonFormsLayoutProps(
  VerticalLayoutWithSpacingRenderer,
);

export const jsonFormVerticalLayoutTester = rankWith(
  1000, // very high rank to ensure it uses this custom renderer
  uiTypeIs('VerticalLayout'),
);
