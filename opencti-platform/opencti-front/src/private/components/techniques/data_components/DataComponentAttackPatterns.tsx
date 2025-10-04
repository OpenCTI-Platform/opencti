import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import { LockPattern } from 'mdi-material-ui';
import { LinkOff } from '@mui/icons-material';
import { deleteNodeFromEdge } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import AddAttackPatterns from './AddAttackPatterns';
import { addAttackPatternsMutationRelationDelete } from './AddAttackPatternsLines';
import { DataComponentAttackPatterns_dataComponent$data } from './__generated__/DataComponentAttackPatterns_dataComponent.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { IconButton, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Skeleton, Typography } from '@components';

const DataComponentAttackPatternsComponent: FunctionComponent<{
  dataComponent: DataComponentAttackPatterns_dataComponent$data;
}> = ({ dataComponent }) => {
  const { t_i18n } = useFormatter();

  const [commit] = useApiMutation(addAttackPatternsMutationRelationDelete);

  const removeAttackPattern = (attackPatternId: string) => {
    commit({
      variables: {
        fromId: dataComponent.id,
        toId: attackPatternId,
        relationship_type: 'detects',
      },
      updater: (store) => deleteNodeFromEdge(
        store,
        'attackPatterns',
        dataComponent.id,
        attackPatternId,
      ),
    });
  };

  return (
    <div
      style={{
        marginTop: 20,
      }}
    >
      <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Attack patterns')}
      </Typography>
      <AddAttackPatterns dataComponent={dataComponent} />
      <div className="clearfix" />
      {dataComponent.attackPatterns && (
        <List style={{ marginTop: -10 }}>
          {dataComponent.attackPatterns.edges
            ?.map((attackPatternEdge) => attackPatternEdge?.node)
            .map((attackPattern, idx) => {
              if (!attackPattern) {
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
                  key={attackPattern.id}
                  dense={true}
                  divider={true}
                  disablePadding={true}
                  secondaryAction={
                    <IconButton
                      aria-label="Remove"
                      onClick={() => removeAttackPattern(attackPattern.id)}
                      size="large"
                    >
                      <LinkOff />
                    </IconButton>
                  }
                >
                  <ListItemButton
                    component={Link}
                    to={`/dashboard/techniques/attack_patterns/${attackPattern.id}`}
                  >
                    <ListItemIcon>
                      <ListItemIcon>
                        <LockPattern color="primary" />
                      </ListItemIcon>
                    </ListItemIcon>
                    <ListItemText primary={attackPattern.name} />
                  </ListItemButton>
                </ListItem>
              );
            })}
        </List>
      )}
    </div>
  );
};

const DataComponentAttackPatterns = createFragmentContainer(
  DataComponentAttackPatternsComponent,
  {
    dataComponent: graphql`
      fragment DataComponentAttackPatterns_dataComponent on DataComponent {
        id
        name
        parent_types
        entity_type
        attackPatterns {
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

export default DataComponentAttackPatterns;
