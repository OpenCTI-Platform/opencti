import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/material/styles';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { DataSourceDetails_dataSource$data, DataSourceDetails_dataSource$key } from './__generated__/DataSourceDetails_dataSource.graphql';
import DataSourceDataComponents from './DataSourceDataComponents';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

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
  const theme = useTheme();

  const data: DataSourceDetails_dataSource$data = useFragment(
    DataSourceDetailsFragment,
    dataSource,
  );

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper
        style={{
          marginTop: theme.spacing(1),
          padding: '15px',
          borderRadius: 4,
        }}
        className={'paper-for-grid'}
        variant="outlined"
      >
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            <FieldOrEmpty source={data.description}>
              <ExpandableMarkdown source={data.description} limit={300} />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Platforms')}
            </Typography>
            <FieldOrEmpty source={data.x_mitre_platforms}>
              {data.x_mitre_platforms?.map((platform) => (
                <ItemOpenVocab
                  key={platform}
                  small={false}
                  type="platforms_ov"
                  value={platform}
                />
              ))}
            </FieldOrEmpty>
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Layers')}
            </Typography>
            <FieldOrEmpty source={data.collection_layers}>
              {data.collection_layers?.map((layer) => (
                <ItemOpenVocab
                  key={layer}
                  small={false}
                  type="collection_layers_ov"
                  value={layer}
                />
              ))}
            </FieldOrEmpty>
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
