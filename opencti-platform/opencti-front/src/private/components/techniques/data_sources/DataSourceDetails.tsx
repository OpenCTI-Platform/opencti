import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { DataSourceDetails_dataSource$data, DataSourceDetails_dataSource$key } from './__generated__/DataSourceDetails_dataSource.graphql';
import DataSourceDataComponents from './DataSourceDataComponents';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';

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

  const data: DataSourceDetails_dataSource$data = useFragment(
    DataSourceDetailsFragment,
    dataSource,
  );

  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={2}>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <FieldOrEmpty source={data.description}>
              <ExpandableMarkdown source={data.description} limit={300} />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Platforms')}
            </Label>
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
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Layers')}
            </Label>
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
      </Card>
    </div>
  );
};
export default DataSourceDetailsComponent;
