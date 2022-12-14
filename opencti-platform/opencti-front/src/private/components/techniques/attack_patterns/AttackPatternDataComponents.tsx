import { createFragmentContainer, graphql, useMutation } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { LinkOff, SourceOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { useFormatter } from '../../../../components/i18n';
import { AttackPatternDataComponents_attackPattern$data } from './__generated__/AttackPatternDataComponents_attackPattern.graphql';
import AddDataComponents from './AddDataComponents';
import { addDataComponentsMutationRelationDelete } from './AddDataComponentsLines';
import { deleteNodeFromEdge } from '../../../../utils/store';

const AttackPatternDataComponentsComponent: FunctionComponent<{ attackPattern: AttackPatternDataComponents_attackPattern$data }> = ({ attackPattern }) => {
  const { t } = useFormatter();

  const [commit] = useMutation(addDataComponentsMutationRelationDelete);

  const removeDataComponent = (dataComponentId: string) => {
    commit({
      variables: {
        fromId: dataComponentId,
        toId: attackPattern.id,
        relationship_type: 'detects',
      },
      updater: (store) => deleteNodeFromEdge(store, 'dataComponents', attackPattern.id, dataComponentId),
    });
  };

  return (
    <div style={{
      marginTop: 20,
    }}>
      <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
        {t('Data components')}
      </Typography>
      <AddDataComponents attackPattern={attackPattern} />
      <div className="clearfix" />
      {attackPattern.dataComponents
        && <List style={{ marginTop: -10 }}>
          {attackPattern.dataComponents.edges?.map((dataComponentEdge) => dataComponentEdge?.node)
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

const AttackPatternDataComponents = createFragmentContainer(
  AttackPatternDataComponentsComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternDataComponents_attackPattern on AttackPattern {
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

export default AttackPatternDataComponents;
