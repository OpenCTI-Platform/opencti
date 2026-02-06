import { createFragmentContainer, graphql } from 'react-relay';
import React, { FunctionComponent } from 'react';
import List from '@mui/material/List';
import { Link } from 'react-router-dom';
import ListItemText from '@mui/material/ListItemText';
import IconButton from '@common/button/IconButton';
import { Delete } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton, Tooltip } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import { useFormatter } from '../../../../components/i18n';
import { AttackPatternDataComponents_attackPattern$data } from './__generated__/AttackPatternDataComponents_attackPattern.graphql';
import AddDataComponents from './AddDataComponents';
import { addDataComponentsMutationRelationDelete } from './AddDataComponentsLines';
import { deleteNodeFromEdge } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Label from '../../../../components/common/label/Label';

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
        <Label action={(
          <AddDataComponents attackPattern={attackPattern} />
        )}
        >
          {t_i18n('Data components')}
        </Label>
      </div>
      <List style={{ paddingTop: 0 }}>
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
                    <Tooltip title={t_i18n('Delete relationship')}>
                      <IconButton
                        aria-label="Remove"
                        onClick={() => removeDataComponent(dataComponent.id)}
                      >
                        <Delete />
                      </IconButton>
                    </Tooltip>
                  )}
                >
                  <ListItemButton
                    component={Link}
                    to={`/dashboard/techniques/data_components/${dataComponent.id}`}
                    sx={{ paddingLeft: 0 }}
                  >
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
