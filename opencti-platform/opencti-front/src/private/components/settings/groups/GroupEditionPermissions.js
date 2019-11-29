import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import {
  compose, map, pathOr, pipe, propEq, find,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemAvatar from '@material-ui/core/ListItemAvatar';
import Checkbox from '@material-ui/core/Checkbox';
import Avatar from '@material-ui/core/Avatar';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { markingDefinitionsSearchQuery } from '../MarkingDefinitions';

const styles = theme => ({
  list: {
    width: '100%',
    maxWidth: 360,
    backgroundColor: theme.palette.background.paper,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
});

const groupMutationRelationAdd = graphql`
  mutation GroupEditionPermissionsMarkingDefinitionsRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    groupEdit(id: $id) {
      relationAdd(input: $input) {
        node {
          ...GroupEditionPermissions_group
        }
      }
    }
  }
`;

const groupMutationRelationDelete = graphql`
  mutation GroupEditionPermissionsMarkingDefinitionsRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    groupEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        node {
          ...GroupEditionPermissions_group
        }
      }
    }
  }
`;

class GroupEditionPermissionsComponent extends Component {
  handleToggle(markingDefinitionId, groupMarkingDefinition, event) {
    if (event.target.checked) {
      commitMutation({
        mutation: groupMutationRelationAdd,
        variables: {
          id: markingDefinitionId,
          input: {
            fromRole: 'allow',
            toId: this.props.group.id,
            toRole: 'allowed',
            through: 'permission',
          },
        },
      });
    } else if (groupMarkingDefinition !== undefined) {
      commitMutation({
        mutation: groupMutationRelationDelete,
        variables: {
          id: this.props.group.id,
          relationId: groupMarkingDefinition.relation,
        },
      });
    }
  }

  render() {
    const { classes, group } = this.props;
    const groupMarkingDefinitions = pipe(
      pathOr([], ['permissions', 'edges']),
      map(n => ({ id: n.node.id, relation: n.relation.id })),
    )(group);

    return (
      <div>
        <QueryRenderer
          query={markingDefinitionsSearchQuery}
          variables={{ search: '' }}
          render={({ props }) => {
            if (props) {
              // Done
              const markingDefinitions = pipe(
                pathOr([], ['markingDefinitions', 'edges']),
                map(n => n.node),
              )(props);
              return (
                <List dense={true} className={classes.root}>
                  {markingDefinitions.map((markingDefinition) => {
                    const groupMarkingDefinition = find(
                      propEq('id', markingDefinition.id),
                    )(groupMarkingDefinitions);
                    return (
                      <ListItem key={markingDefinition.id} divider={true}>
                        <ListItemAvatar>
                          <Avatar className={classes.avatar}>
                            {markingDefinition.definition.charAt(0)}
                          </Avatar>
                        </ListItemAvatar>
                        <ListItemText primary={markingDefinition.definition} />
                        <ListItemSecondaryAction>
                          <Checkbox
                            onChange={this.handleToggle.bind(
                              this,
                              markingDefinition.id,
                              groupMarkingDefinition,
                            )}
                            checked={groupMarkingDefinition !== undefined}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                    );
                  })}
                </List>
              );
            }
            // Loading
            return <List> &nbsp; </List>;
          }}
        />
      </div>
    );
  }
}

GroupEditionPermissionsComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  group: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

const GroupEditionPermissions = createFragmentContainer(
  GroupEditionPermissionsComponent,
  {
    group: graphql`
      fragment GroupEditionPermissions_group on Group {
        id
        permissions {
          edges {
            node {
              id
              definition
              definition_type
            }
            relation {
              id
            }
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(GroupEditionPermissions);
