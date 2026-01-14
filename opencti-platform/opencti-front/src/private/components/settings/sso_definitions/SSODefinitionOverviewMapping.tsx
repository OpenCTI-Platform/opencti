import { Grid2 as Grid } from '@mui/material';
import React from 'react';
import Card from '@common/card/Card';

// interface SSODefinitionOverviewMappingProps {
//   sso: SSODefinition;
// }

const SSODefinitionOverviewMapping = (
  // { sso }: SSODefinitionOverviewMappingProps
) => {
  // const theme = useTheme<Theme>();
  // const { t_i18n, fldt, n } = useFormatter();
  // const sso = useFragment(mappingFragment, sso);

  return (
    <Grid size={{ xs: 12 }}>
      <Card
        title="SSO Mapping"
      >
      </Card>
    </Grid>
  );
};

export default SSODefinitionOverviewMapping;
