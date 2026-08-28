import React from 'react';
import * as PropTypes from 'prop-types';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import { LockPattern } from 'mdi-material-ui';
import { graphql, createFragmentContainer } from 'react-relay';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import Label from '../../../../components/common/label/Label';

const AttackPatternParentAttackPatternsComponent = (props) => {
  const { t_i18n } = useFormatter();
  const { attackPattern } = props;
  return (
    <div>
      <Label>
        {t_i18n('Parent attack patterns')}
      </Label>
      <List>
        {attackPattern.parentAttackPatterns.edges.map(
          (parentAttackPatternEdge) => {
            const parentAttackPattern = parentAttackPatternEdge.node;
            return (
              <ListItemButton
                key={parentAttackPattern.id}
                dense={true}
                divider={true}
                component={Link}
                to={`/dashboard/techniques/attack_patterns/${parentAttackPattern.id}`}
              >
                <ListItemIcon>
                  <LockPattern color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary={`[${parentAttackPattern.x_mitre_id}] ${parentAttackPattern.name}`}
                />
              </ListItemButton>
            );
          },
        )}
      </List>
    </div>
  );
};

AttackPatternParentAttackPatternsComponent.propTypes = {
  classes: PropTypes.object,
  attackPattern: PropTypes.object,
};

const AttackPatternParentAttackPatterns = createFragmentContainer(
  AttackPatternParentAttackPatternsComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternParentAttackPatterns_attackPattern on AttackPattern {
        id
        parentAttackPatterns {
          edges {
            node {
              id
              name
              description
              x_mitre_id
            }
          }
        }
      }
    `,
  },
);

export default AttackPatternParentAttackPatterns;
