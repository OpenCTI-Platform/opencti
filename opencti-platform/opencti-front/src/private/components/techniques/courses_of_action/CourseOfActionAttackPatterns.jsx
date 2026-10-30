import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { filter } from 'ramda';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Avatar from '@mui/material/Avatar';
import { Link } from 'react-router';
import IconButton from '@common/button/IconButton';
import { ExpandLessOutlined, ExpandMoreOutlined, LinkOff } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import * as R from 'ramda';
import { Box, ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import { truncate } from '../../../../utils/String';
import AddAttackPatterns from './AddAttackPatterns';
import { addAttackPatternsLinesMutationRelationDelete } from './AddAttackPatternsLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Label from '../../../../components/common/label/Label';

class CourseOfActionAttackPatternComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      expanded: false,
    };
  }

  handleToggleExpand() {
    this.setState({ expanded: !this.state.expanded });
  }

  removeAttackPattern(attackPatternEdge) {
    commitMutation({
      mutation: addAttackPatternsLinesMutationRelationDelete,
      variables: {
        fromId: this.props.courseOfAction.id,
        toId: attackPatternEdge.node.id,
        relationship_type: 'mitigates',
      },
      updater: (store) => {
        const node = store.get(this.props.courseOfAction.id);
        const attackPatterns = node.getLinkedRecord('attackPatterns');
        const edges = attackPatterns.getLinkedRecords('edges');
        const newEdges = filter(
          (n) => n.getLinkedRecord('node').getValue('id')
            !== attackPatternEdge.node.id,
          edges,
        );
        attackPatterns.setLinkedRecords(newEdges, 'edges');
      },
    });
  }

  render() {
    const { t, courseOfAction } = this.props;
    const { expanded } = this.state;
    const attackPatternsEdges = courseOfAction.attackPatterns.edges;
    const expandable = attackPatternsEdges.length > 7;
    return (
      <Box sx={{ marginTop: 2 }}>
        <Label action={(
          <>
            <AddAttackPatterns
              courseOfAction={courseOfAction}
              courseOfActionAttackPatterns={courseOfAction.attackPatterns.edges}
            />
            {expandable && (
              <IconButton
                aria-label={expanded ? t('Collapse') : t('Expand')}
                color="primary"
                onClick={this.handleToggleExpand.bind(this)}
                aria-expanded={expanded}
              >
                {expanded ? <ExpandLessOutlined /> : <ExpandMoreOutlined />}
              </IconButton>
            )}
          </>
        )}
        >
          {t('Mitigated attack patterns')}
        </Label>
        <List sx={{ padding: 0 }}>
          {R.take(expanded ? 200 : 7, attackPatternsEdges).map(
            (attackPatternEdge) => {
              const attackPattern = attackPatternEdge.node;
              return (
                <ListItem
                  key={attackPattern.id}
                  dense={true}
                  divider={true}
                  disablePadding={true}
                  secondaryAction={(
                    <IconButton
                      aria-label="Remove"
                      onClick={this.removeAttackPattern.bind(
                        this,
                        attackPatternEdge,
                      )}
                    >
                      <LinkOff />
                    </IconButton>
                  )}
                >
                  <ListItemButton
                    component={Link}
                    to={`/dashboard/techniques/attack_patterns/${attackPattern.id}`}
                  >
                    <ListItemIcon>
                      <Avatar
                        sx={{
                          width: 24,
                          height: 24,
                          backgroundColor: 'primary.main',
                        }}
                      >
                        {attackPattern.name.substring(0, 1)}
                      </Avatar>
                    </ListItemIcon>
                    <ListItemText
                      primary={attackPattern.name}
                      secondary={truncate(attackPattern.description, 60)}
                    />
                  </ListItemButton>
                </ListItem>
              );
            },
          )}
        </List>
      </Box>
    );
  }
}

CourseOfActionAttackPatternComponent.propTypes = {
  t: PropTypes.func,
  fld: PropTypes.func,
  courseOfAction: PropTypes.object,
};

const CourseOfActionAttackPattern = createFragmentContainer(
  CourseOfActionAttackPatternComponent,
  {
    courseOfAction: graphql`
      fragment CourseOfActionAttackPatterns_courseOfAction on CourseOfAction {
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

export default inject18n(CourseOfActionAttackPattern);
