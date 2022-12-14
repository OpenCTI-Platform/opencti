import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql, useMutation } from 'react-relay';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ListItemSecondaryAction } from '@mui/material';
import IconButton from '@mui/material/IconButton';
import { LinkOff, SourceOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { useFormatter } from '../../../../components/i18n';
import AddDataComponents from './AddDataComponents';
import { addDataComponentsMutationRelationDelete } from './AddDataComponentsLines';
import { DataSourceDataComponents_dataSource$data } from './__generated__/DataSourceDataComponents_dataSource.graphql';

const DataSourceDataComponentsComponent: FunctionComponent<{ dataSource: DataSourceDataComponents_dataSource$data }> = ({ dataSource }) => {
  const { t } = useFormatter();

  const [commit] = useMutation(addDataComponentsMutationRelationDelete);

  const removeDataComponent = (dataComponentId: string) => commit({
    variables: {
      id: dataSource.id,
      dataComponentId,
    },
  });

  return (
    <div>
      <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
        {t('Data components')}
      </Typography>
      <AddDataComponents dataSource={dataSource} />
      <div className="clearfix" />
      {dataSource.dataComponents
        && <List style={{ marginTop: -10 }}>
          {dataSource.dataComponents.edges?.map((node) => node?.node)
            .map((dataComponent, idx) => {
              if (!dataComponent) {
                return <ListItemText
                  key={idx}
                  primary={
                    <Skeleton
                      animation="wave"
                      variant="rectangular"
                      width="90%"
                      height="100%"
                    />
                  }
                />;
              }
              return (
                <ListItem
                  key={dataComponent.id}
                  dense={true}
                  divider={true}
                  button={true}
                  component={Link}
                  to={`/dashboard/techniques/data_components/${dataComponent.id}`}
                >
                  <ListItemIcon>
                    <ListItemIcon>
                      <SourceOutlined color="primary" />
                    </ListItemIcon>
                  </ListItemIcon>
                  <ListItemText primary={dataComponent.name} />
                  <ListItemSecondaryAction>
                    <IconButton
                      aria-label="Remove"
                      onClick={() => removeDataComponent(dataComponent.id)}
                      size="large"
                    >
                      <LinkOff />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              );
            })}
        </List>
      }
    </div>
  );
};

const DataSourceDataComponents = createFragmentContainer(
  DataSourceDataComponentsComponent,
  {
    dataSource: graphql`
      fragment DataSourceDataComponents_dataSource on DataSource {
        id
        dataComponents {
          edges {
            node {
              id
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
