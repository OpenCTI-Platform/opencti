import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import IconButton from '@material-ui/core/IconButton';
import { LockPattern } from 'mdi-material-ui';
import { LinkOff } from '@material-ui/icons';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import AddSubAttackPattern from './AddSubAttackPattern';
import { addSubAttackPatternsMutationRelationDelete } from './AddSubAttackPatternsLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

class AttackPatternSubAttackPatternsComponent extends Component {
  removeSubAttackPattern(subAttackPatternEdge) {
    commitMutation({
      mutation: addSubAttackPatternsMutationRelationDelete,
      variables: {
        fromId: subAttackPatternEdge.node.id,
        toId: this.props.attackPattern.id,
        relationship_type: 'subtechnique-of',
      },
      updater: (store) => {
        const node = store.get(this.props.attackPattern.id);
        const subAttackPatterns = node.getLinkedRecord('subAttackPatterns');
        const edges = subAttackPatterns.getLinkedRecords('edges');
        const newEdges = filter(
          (n) => n.getLinkedRecord('node').getValue('id')
            !== subAttackPatternEdge.node.id,
          edges,
        );
        subAttackPatterns.setLinkedRecords(newEdges, 'edges');
      },
    });
  }

  render() {
    const { t, attackPattern } = this.props;
    return (
      <div style={{ height: '100%', marginTop: 20 }}>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Sub attack patterns')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <AddSubAttackPattern
            attackPatternId={attackPattern.id}
            attackPatternSubAttackPatterns={
              attackPattern.subAttackPatterns.edges
            }
          />
        </Security>
        <div className="clearfix" />
        <List style={{ marginTop: -10 }}>
          {attackPattern.subAttackPatterns.edges.map((subAttackPatternEdge) => {
            const subAttackPattern = subAttackPatternEdge.node;
            return (
              <ListItem
                key={subAttackPattern.id}
                dense={true}
                divider={true}
                button={true}
                component={Link}
                to={`/dashboard/arsenal/attack_patterns/${subAttackPattern.id}`}
              >
                <ListItemIcon>
                  <LockPattern color="primary" />
                </ListItemIcon>
                <ListItemText primary={subAttackPattern.name} />
                <ListItemSecondaryAction>
                  <IconButton
                    aria-label="Remove"
                    onClick={this.removeSubAttackPattern.bind(
                      this,
                      subAttackPatternEdge,
                    )}
                  >
                    <LinkOff />
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
      </div>
    );
  }
}

AttackPatternSubAttackPatternsComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  attackPattern: PropTypes.object,
};

const AttackPatternSubAttackPatterns = createFragmentContainer(
  AttackPatternSubAttackPatternsComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternSubAttackPatterns_attackPattern on AttackPattern {
        id
        subAttackPatterns {
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

export default compose(inject18n)(AttackPatternSubAttackPatterns);
