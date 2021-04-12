import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { Link } from 'react-router-dom';
import { LockPattern } from 'mdi-material-ui';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';

class AttackPatternParentAttackPatternsComponent extends Component {
  render() {
    const { t, attackPattern } = this.props;
    return (
      <div>
        <Typography variant="h3" gutterBottom={true}>
          {t('Parent attack patterns')}
        </Typography>
        <List>
          {attackPattern.parentAttackPatterns.edges.map(
            (parentAttackPatternEdge) => {
              const parentAttackPattern = parentAttackPatternEdge.node;
              return (
                <ListItem
                  key={parentAttackPattern.id}
                  dense={true}
                  divider={true}
                  button={true}
                  component={Link}
                  to={`/dashboard/arsenal/attack_patterns/${parentAttackPattern.id}`}
                >
                  <ListItemIcon>
                    <LockPattern color="primary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={`[${parentAttackPattern.x_mitre_id}] ${parentAttackPattern.name}`}
                  />
                </ListItem>
              );
            },
          )}
        </List>
      </div>
    );
  }
}

AttackPatternParentAttackPatternsComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
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

export default compose(inject18n)(AttackPatternParentAttackPatterns);
