import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Avatar from '@mui/material/Avatar';
import { Link } from 'react-router-dom';
import IconButton from '@common/button/IconButton';
import { ExpandLessOutlined, ExpandMoreOutlined, LinkOff } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import * as R from 'ramda';
import { ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import { truncate } from '../../../../utils/String';
import AddAttackPatterns from './AddAttackPatterns';
import { addAttackPatternsLinesMutationRelationDelete } from './AddAttackPatternsLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  list: {
    padding: 0,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

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
    const { t, classes, courseOfAction } = this.props;
    const { expanded } = this.state;
    const attackPatternsEdges = courseOfAction.attackPatterns.edges;
    const expandable = attackPatternsEdges.length > 7;
    return (
      <div style={{ marginTop: 20 }}>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Mitigated attack patterns')}
        </Typography>
        <AddAttackPatterns
          courseOfAction={courseOfAction}
          courseOfActionAttackPatterns={courseOfAction.attackPatterns.edges}
        />
        <div style={{ float: 'right', margin: '-10px 15px 0 0' }}>
          {expandable && (
            <IconButton
              color="primary"
              onClick={this.handleToggleExpand.bind(this)}
            >
              {expanded ? <ExpandLessOutlined /> : <ExpandMoreOutlined />}
            </IconButton>
          )}
        </div>
        <div className="clearfix" />
        <List classes={{ root: classes.list }}>
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
                      <Avatar classes={{ root: classes.avatar }}>
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
      </div>
    );
  }
}

CourseOfActionAttackPatternComponent.propTypes = {
  classes: PropTypes.object,
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

export default compose(
  inject18n,
  withStyles(styles),
)(CourseOfActionAttackPattern);
