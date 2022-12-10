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

const styles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));

const DataComponentDetailsFragment = graphql`
  fragment DataComponentDetails_dataComponent on DataComponent {
    id
    description
    creator {
      id
      name
    }
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
    ...DataComponentDataSources_dataComponent
    ...DataComponentAttackPatterns_dataComponent
  }
`;

interface DataComponentDetailsProps {
  dataComponent: DataComponentDetails_dataComponent$key
}

const DataComponentDetails: FunctionComponent<DataComponentDetailsProps> = ({ dataComponent }) => {
  const { t } = useFormatter();
  const classes = styles();

  const data: DataComponentDetails_dataComponent$data = useFragment(DataComponentDetailsFragment, dataComponent);

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
            <Grid item={true} xs={12}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              {data.description && (
              <ExpandableMarkdown
                source={data.description}
                limit={300}
              />
              )}
            </Grid>
          <Grid item={true} xs={12}>
            <DataComponentDataSource dataComponent={data} />
            <DataComponentAttackPatterns dataComponent={data} />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default DataComponentDetails;
