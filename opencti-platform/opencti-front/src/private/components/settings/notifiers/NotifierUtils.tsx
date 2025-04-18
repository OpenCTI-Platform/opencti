import React, { ReactNode } from 'react';
import Grid from '@mui/material/Grid';
import { UiSchema } from '@rjsf/utils';

const ObjectFieldTemplate = ({
  properties,
}: { properties: { content: ReactNode }[] }) => {
  return (
    <>
      <Grid container={true} spacing={2} style={{ marginTop: 0 }}>
        {properties.map((element, index) => (
          <Grid
            item={true}
            xs={12}
            key={index}
            style={{ marginTop: -5 }}
          >
            {element.content}
          </Grid>
        ))}
      </Grid>
    </>
  );
};

// eslint-disable-next-line import/prefer-default-export
export const uiSchema: UiSchema = {
  'ui:ObjectFieldTemplate': ObjectFieldTemplate,
  'ui:options': {
    orderable: false,
    submitButtonOptions: {
      norender: true,
    },
  },
};
