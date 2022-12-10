import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql, useMutation } from 'react-relay';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import { ProgressWrench } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { LinkOff } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { deleteNodeFromEdge } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import AddAttackPatterns from './AddAttackPatterns';
import { addAttackPatternsMutationRelationDelete } from './AddAttackPatternsLines';
import { DataComponentAttackPatterns_dataComponent$data } from './__generated__/DataComponentAttackPatterns_dataComponent.graphql';

const DataComponentAttackPatternsComponent: FunctionComponent<{ dataComponent: DataComponentAttackPatterns_dataComponent$data }> = ({ dataComponent }) => {
  const { t } = useFormatter();

  const [commit] = useMutation(addAttackPatternsMutationRelationDelete);

  const removeAttackPattern = (attackPatternId: string) => {
    commit({
      variables: {
        fromId: dataComponent.id,
        toId: attackPatternId,
        relationship_type: 'detects',
      },
      updater: (store) => deleteNodeFromEdge(store, 'attackPatterns', dataComponent.id, attackPatternId),
    });
  };

  return (
    <div style={{
      marginTop: 20,
    }}>
      <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
        {t('Attack patterns')}
      </Typography>
      <AddAttackPatterns dataComponent={dataComponent} />
      <div className="clearfix" />
      {dataComponent.attackPatterns
        && <List style={{ marginTop: -10 }}>
          {dataComponent.attackPatterns.edges?.map((attackPatternEdge) => attackPatternEdge?.node)
            .map((attackPattern, idx) => {
              if (!attackPattern) {
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
                  key={attackPattern.id}
                  dense={true}
                  divider={true}
                  button={true}
                  component={Link}
                  to={`/dashboard/techniques/attack_patterns/${attackPattern.id}`}
                >
                  <ListItemIcon>
                    <ListItemIcon>
                      <ProgressWrench color="primary" />
                    </ListItemIcon>
                  </ListItemIcon>
                  <ListItemText primary={attackPattern.name} />
                  <ListItemSecondaryAction>
                    <IconButton
                      aria-label="Remove"
                      onClick={() => removeAttackPattern(attackPattern.id)}
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

const DataComponentAttackPatterns = createFragmentContainer(
  DataComponentAttackPatternsComponent,
  {
    dataComponent: graphql`
      fragment DataComponentAttackPatterns_dataComponent on DataComponent {
        id
        attackPatterns {
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

export default DataComponentAttackPatterns;
