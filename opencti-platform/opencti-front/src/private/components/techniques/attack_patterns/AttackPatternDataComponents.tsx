import { createFragmentContainer, graphql } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import IconButton from '@common/button/IconButton';
import { LinkOff, SourceOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import { useFormatter } from '../../../../components/i18n';
import { AttackPatternDataComponents_attackPattern$data } from './__generated__/AttackPatternDataComponents_attackPattern.graphql';
import AddDataComponents from './AddDataComponents';
import { addDataComponentsMutationRelationDelete } from './AddDataComponentsLines';
import { deleteNodeFromEdge } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

const AttackPatternDataComponentsComponent: FunctionComponent<{
  attackPattern: AttackPatternDataComponents_attackPattern$data;
}> = ({ attackPattern }) => {
  const { t_i18n } = useFormatter();

  const [commit] = useApiMutation(addDataComponentsMutationRelationDelete);

  const removeDataComponent = (dataComponentId: string) => {
    commit({
      variables: {
        fromId: dataComponentId,
        toId: attackPattern.id,
        relationship_type: 'detects',
      },
      updater: (store) => deleteNodeFromEdge(
        store,
        'dataComponents',
        attackPattern.id,
        dataComponentId,
      ),
    });
  };

  return (
    <div
      style={{
        marginTop: 20,
      }}
    >
      <div style={{ display: 'flex', flexDirection: 'row' }}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Data components')}
        </Typography>
        <AddDataComponents attackPattern={attackPattern} />
        <div className="clearfix" />
      </div>
      <List style={{ marginTop: -10, paddingTop: 0 }}>
        <FieldOrEmpty source={attackPattern.dataComponents?.edges}>
          {attackPattern.dataComponents?.edges
            ?.map((dataComponentEdge) => dataComponentEdge?.node)
            .map((dataComponent, idx) => {
              if (!dataComponent) {
                return (
                  <ListItemText
                    key={idx}
                    primary={(
                      <Skeleton
                        animation="wave"
                        variant="rectangular"
                        width="90%"
                        height="100%"
                      />
                    )}
                  />
                );
              }
              return (
                <ListItem
                  key={dataComponent.id}
                  dense={true}
                  divider={true}
                  disablePadding={true}
                  secondaryAction={(
                    <IconButton
                      aria-label="Remove"
                      onClick={() => removeDataComponent(dataComponent.id)}
                    >
                      <LinkOff />
                    </IconButton>
                  )}
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
        </FieldOrEmpty>
      </List>
    </div>
  );
};

const AttackPatternDataComponents = createFragmentContainer(
  AttackPatternDataComponentsComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternDataComponents_attackPattern on AttackPattern {
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

export default AttackPatternDataComponents;
