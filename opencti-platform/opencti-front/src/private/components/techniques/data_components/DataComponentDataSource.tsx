import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ListItemSecondaryAction } from '@mui/material';
import IconButton from '@mui/material/IconButton';
import { LinkOff, StreamOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import AddDataSources from './AddDataSources';
import { DataComponentDataSources_dataComponent$data, DataComponentDataSources_dataComponent$key } from './__generated__/DataComponentDataSources_dataComponent.graphql';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { KnowledgeSecurity } from '../../../../utils/Security';

const dataComponentDataSourcesRemoveMutation = graphql`
  mutation DataComponentDataSourcesRemoveMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    dataComponentFieldPatch(id: $id, input: $input) {
      ...DataComponentEditionOverview_dataComponent
      ...DataComponent_dataComponent
    }
  }
`;

const DataComponentDataSourceFragment = graphql`
  fragment DataComponentDataSources_dataComponent on DataComponent {
    id
    dataSource {
      id
      name
      description
    }
  }
`;

interface DataComponentDataSourcesProps {
  dataComponent: DataComponentDataSources_dataComponent$key;
}

const DataComponentDataSource: FunctionComponent<
DataComponentDataSourcesProps
> = ({ dataComponent }) => {
  const { t_i18n } = useFormatter();

  const data: DataComponentDataSources_dataComponent$data = useFragment(
    DataComponentDataSourceFragment,
    dataComponent,
  );

  const dataSourceId: string | undefined = data.dataSource?.id;

  const [commit] = useMutation(dataComponentDataSourcesRemoveMutation);

  const removeDataSource = () => {
    commit({
      variables: {
        id: data.id,
        input: { key: 'dataSource', value: [null] },
      },
    });
  };

  return (
    <div>
      <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Data source')}
      </Typography>
      {!dataSourceId && <AddDataSources dataComponentId={data.id} />}
      <div className="clearfix" />
      <List style={{ marginTop: -10 }}>
        {dataSourceId && (
          <ListItem
            key={data.dataSource?.id}
            dense={true}
            divider={true}
            button={true}
            component={Link}
            to={`/dashboard/techniques/data_sources/${dataSourceId}`}
          >
            <ListItemIcon>
              <ListItemIcon>
                <StreamOutlined color="primary" />
              </ListItemIcon>
            </ListItemIcon>
            <ListItemText primary={data.dataSource?.name} />
            <ListItemSecondaryAction>
              <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Data-Component'>
                <IconButton
                  aria-label="Remove"
                  onClick={removeDataSource}
                  size="large"
                >
                  <LinkOff />
                </IconButton>
              </KnowledgeSecurity>
            </ListItemSecondaryAction>
          </ListItem>
        )}
      </List>
    </div>
  );
};

export default DataComponentDataSource;
