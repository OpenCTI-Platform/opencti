import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { DataComponentDetails_dataComponent$data, DataComponentDetails_dataComponent$key } from './__generated__/DataComponentDetails_dataComponent.graphql';
import DataComponentDataSource from './DataComponentDataSource';
import DataComponentAttackPatterns from './DataComponentAttackPatterns';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';

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

  const data: DataComponentDetails_dataComponent$data = useFragment(
    DataComponentDetailsFragment,
    dataComponent,
  );

  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={2}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <FieldOrEmpty source={data.description}>
              <ExpandableMarkdown source={data.description} limit={300} />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={12}>
            <DataComponentDataSource dataComponent={data} />
            <DataComponentAttackPatterns dataComponent={data} />
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

export default DataComponentDetails;
