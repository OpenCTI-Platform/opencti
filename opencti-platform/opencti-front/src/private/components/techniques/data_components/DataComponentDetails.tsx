import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { DataComponentDetails_dataComponent$data, DataComponentDetails_dataComponent$key } from './__generated__/DataComponentDetails_dataComponent.graphql';
import DataComponentDataSource from './DataComponentDataSource';
import DataComponentAttackPatterns from './DataComponentAttackPatterns';
import type { Theme } from '../../../../components/Theme';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
}));

const DataComponentDetailsFragment = graphql`
  fragment DataComponentDetails_dataComponent on DataComponent {
    id
    description
    objectLabel {
      id
      value
      color
    }
    ...DataComponentDataSources_dataComponent
    ...DataComponentAttackPatterns_dataComponent
  }
`;

interface DataComponentDetailsProps {
  dataComponent: DataComponentDetails_dataComponent$key;
}

const DataComponentDetails: FunctionComponent<DataComponentDetailsProps> = ({
  dataComponent,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const data: DataComponentDetails_dataComponent$data = useFragment(
    DataComponentDetailsFragment,
    dataComponent,
  );

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            {data.description && (
              <ExpandableMarkdown source={data.description} limit={300} />
            )}
          </Grid>
          <Grid item xs={12}>
            <DataComponentDataSource dataComponent={data} />
            <DataComponentAttackPatterns dataComponent={data} />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default DataComponentDetails;
