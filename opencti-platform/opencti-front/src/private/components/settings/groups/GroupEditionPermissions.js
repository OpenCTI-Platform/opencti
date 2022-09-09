import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { compose, map, pathOr, pipe, propEq, find } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import Checkbox from '@mui/material/Checkbox';
import Alert from '@mui/lab/Alert/Alert';
import { CenterFocusStrongOutlined } from '@mui/icons-material';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { markingDefinitionsLinesSearchQuery } from '../marking_definitions/MarkingDefinitionsLines';

const styles = (theme) => ({
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
    $input: InternalRelationshipAddInput
  ) {
    groupEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...GroupEditionPermissions_group
        }
      }
    }
  }
`;

const groupMutationRelationDelete = graphql`
  mutation GroupEditionPermissionsMarkingDefinitionsRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    groupEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...GroupEditionPermissions_group
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
          id: this.props.group.id,
          input: {
            toId: markingDefinitionId,
            relationship_type: 'accesses-to',
          },
        },
      });
    } else if (groupMarkingDefinition !== undefined) {
      commitMutation({
        mutation: groupMutationRelationDelete,
        variables: {
          id: this.props.group.id,
          toId: markingDefinitionId,
          relationship_type: 'accesses-to',
        },
      });
    }
  }

  render() {
    const { classes, group, t } = this.props;
    const groupMarkingDefinitions = group.allowed_marking || [];
    return (
      <div style={{ paddingTop: 15 }}>
        <Alert severity="warning" style={{ marginBottom: 10 }}>
          {t(
            'All users of this group will be able to view entities and relationships marked with checked marking definitions, including statements and special markings.',
          )}
        </Alert>
        <QueryRenderer
          query={markingDefinitionsLinesSearchQuery}
          variables={{ search: '' }}
          render={({ props }) => {
            if (props) {
              // Done
              const markingDefinitions = pipe(
                pathOr([], ['markingDefinitions', 'edges']),
                map((n) => n.node),
              )(props);
              return (
                <List className={classes.root}>
                  {markingDefinitions.map((markingDefinition) => {
                    const groupMarkingDefinition = find(
                      propEq('id', markingDefinition.id),
                    )(groupMarkingDefinitions);
                    return (
                      <ListItem key={markingDefinition.id} divider={true}>
                        <ListItemIcon color="primary">
                          <CenterFocusStrongOutlined />
                        </ListItemIcon>
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
};

const GroupEditionPermissions = createFragmentContainer(
  GroupEditionPermissionsComponent,
  {
    group: graphql`
      fragment GroupEditionPermissions_group on Group {
        id
        default_assignation
        allowed_marking {
          id
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(GroupEditionPermissions);
