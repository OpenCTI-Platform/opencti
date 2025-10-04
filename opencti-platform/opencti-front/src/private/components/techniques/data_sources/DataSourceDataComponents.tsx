import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import { LinkOff, SourceOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import AddDataComponents from './AddDataComponents';
import { addDataComponentsMutationRelationDelete } from './AddDataComponentsLines';
import { DataSourceDataComponents_dataSource$data } from './__generated__/DataSourceDataComponents_dataSource.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { IconButton, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Skeleton, Typography } from '@components';

const DataSourceDataComponentsComponent: FunctionComponent<{
  dataSource: DataSourceDataComponents_dataSource$data;
}> = ({ dataSource }) => {
  const { t_i18n } = useFormatter();

  const [commit] = useApiMutation(addDataComponentsMutationRelationDelete);

  const removeDataComponent = (dataComponentId: string) => commit({
    variables: {
      id: dataSource.id,
      dataComponentId,
    },
  });

  return (
    <div>
      <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Data components')}
      </Typography>
      <AddDataComponents dataSource={dataSource} />
      <div className="clearfix" />
      {dataSource.dataComponents && (
        <List style={{ marginTop: -10 }}>
          {dataSource.dataComponents.edges
            ?.map((node) => node?.node)
            .map((dataComponent, idx) => {
              if (!dataComponent) {
                return (
                  <ListItemText
                    key={idx}
                    primary={
                      <Skeleton
                        animation="wave"
                        variant="rectangular"
                        width="90%"
                        height="100%"
                      />
                    }
                  />
                );
              }
              return (
                <ListItem
                  key={dataComponent.id}
                  dense={true}
                  divider={true}
                  disablePadding={true}
                  secondaryAction={
                    <IconButton
                      aria-label="Remove"
                      onClick={() => removeDataComponent(dataComponent.id)}
                      size="large"
                    >
                      <LinkOff />
                    </IconButton>
                  }
                >
                  <ListItemButton
                    component={Link}
                    to={`/dashboard/techniques/data_components/${dataComponent.id}`}
                  >
                    <ListItemIcon>
                      <ListItemIcon>
                        <SourceOutlined color="primary" />
                      </ListItemIcon>
                    </ListItemIcon>
                    <ListItemText primary={dataComponent.name} />
                  </ListItemButton>
                </ListItem>
              );
            })}
        </List>
      )}
    </div>
  );
};

const DataSourceDataComponents = createFragmentContainer(
  DataSourceDataComponentsComponent,
  {
    dataSource: graphql`
      fragment DataSourceDataComponents_dataSource on DataSource {
        id
        name
        parent_types
        entity_type
        dataComponents {
          edges {
            node {
              id
              parent_types
              name
              description
            }
          }
        }
      }
    `,
  },
);

export default DataSourceDataComponents;
