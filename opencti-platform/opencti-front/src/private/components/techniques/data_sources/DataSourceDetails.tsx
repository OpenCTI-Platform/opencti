import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { DataSourceDetails_dataSource$data, DataSourceDetails_dataSource$key } from './__generated__/DataSourceDetails_dataSource.graphql';
import DataSourceDataComponents from './DataSourceDataComponents';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
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

const DataSourceDetailsFragment = graphql`
  fragment DataSourceDetails_dataSource on DataSource {
    id
    name
    description
    x_mitre_platforms
    collection_layers
    objectLabel {
      id
      value
      color
    }
    ...DataSourceDataComponents_dataSource
  }
`;

interface DataSourceDetailsProps {
  dataSource: DataSourceDetails_dataSource$key;
}

const DataSourceDetailsComponent: FunctionComponent<DataSourceDetailsProps> = ({
  dataSource,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const data: DataSourceDetails_dataSource$data = useFragment(
    DataSourceDetailsFragment,
    dataSource,
  );

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            {data.description && (
              <ExpandableMarkdown source={data.description} limit={300} />
            )}
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Platforms')}
            </Typography>
            {data.x_mitre_platforms?.map((platform) => (
              <ItemOpenVocab
                key={platform}
                small={false}
                type="platforms_ov"
                value={platform}
              />
            ))}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Layers')}
            </Typography>
            {data.collection_layers?.map((layer) => (
              <ItemOpenVocab
                key={layer}
                small={false}
                type="collection_layers_ov"
                value={layer}
              />
            ))}
          </Grid>
          <Grid item xs={12}>
            <DataSourceDataComponents dataSource={data} />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};
export default DataSourceDetailsComponent;
