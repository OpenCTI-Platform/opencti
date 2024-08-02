import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { LockPattern } from 'mdi-material-ui';
import { LinkOff } from '@mui/icons-material';
import { createFragmentContainer, graphql } from 'react-relay';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import AddSubAttackPattern from './AddSubAttackPattern';
import { addSubAttackPatternsMutationRelationDelete } from './AddSubAttackPatternsLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

class AttackPatternSubAttackPatternsComponent extends Component {
  removeSubAttackPattern(subAttackPattern) {
    commitMutation({
      mutation: addSubAttackPatternsMutationRelationDelete,
      variables: {
        fromId: subAttackPattern.id,
        toId: this.props.attackPattern.id,
        relationship_type: 'subtechnique-of',
      },
      updater: (store) => {
        const node = store.get(this.props.attackPattern.id);
        const subAttackPatterns = node.getLinkedRecord('subAttackPatterns');
        const edges = subAttackPatterns.getLinkedRecords('edges');
        const newEdges = R.filter(
          (n) => n.getLinkedRecord('node').getValue('id') !== subAttackPattern.id,
          edges,
        );
        subAttackPatterns.setLinkedRecords(newEdges, 'edges');
      },
    });
  }

  render() {
    const { t, attackPattern } = this.props;
    const sortByXMitreIdCaseInsensitive = R.sortBy(
      R.compose(R.toLower, R.propOr('', 'x_mitre_id')),
    );
    const subAttackPatterns = R.pipe(
      R.map((n) => n.node),
      sortByXMitreIdCaseInsensitive,
    )(attackPattern.subAttackPatterns.edges);
    return (
      <div style={{ height: '100%', marginTop: 20 }}>
        <div style={{ display: 'flex', flexDirection: 'row' }}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Sub attack patterns')}
          </Typography>
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <AddSubAttackPattern
              attackPattern={attackPattern}
              attackPatternSubAttackPatterns={
              attackPattern.subAttackPatterns.edges
            }
            />
          </Security>
          <div className="clearfix"/>
        </div>
        <List style={{ marginTop: -10, paddingTop: 0 }}>
          <FieldOrEmpty source={subAttackPatterns}>
            {subAttackPatterns.map((subAttackPattern) => (
              <ListItem
                key={subAttackPattern.id}
                dense={true}
                divider={true}
                button={true}
                component={Link}
                to={`/dashboard/techniques/attack_patterns/${subAttackPattern.id}`}
              >
                <ListItemIcon>
                  <LockPattern color="primary"/>
                </ListItemIcon>
                <ListItemText
                  primary={`[${subAttackPattern.x_mitre_id}] ${subAttackPattern.name}`}
                />
                <ListItemSecondaryAction>
                  <IconButton
                    aria-label="Remove"
                    onClick={this.removeSubAttackPattern.bind(
                      this,
                      subAttackPattern,
                    )}
                    size="large"
                  >
                    <LinkOff/>
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItem>
            ))}
          </FieldOrEmpty>
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
        name
        parent_types
        entity_type
        subAttackPatterns {
          edges {
            node {
              id
              parent_types
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

export default R.compose(inject18n)(AttackPatternSubAttackPatterns);
