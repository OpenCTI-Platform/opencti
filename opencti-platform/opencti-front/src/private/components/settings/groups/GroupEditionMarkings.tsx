import React from 'react';
import { createFragmentContainer, graphql, useMutation } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import Checkbox from '@mui/material/Checkbox';
import Alert from '@mui/lab/Alert/Alert';
import { CenterFocusStrongOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { markingDefinitionsLinesSearchQuery } from '../marking_definitions/MarkingDefinitionsLines';
import {
  MarkingDefinitionsLinesSearchQuery$data,
} from '../marking_definitions/__generated__/MarkingDefinitionsLinesSearchQuery.graphql';
import { Theme } from '../../../../components/Theme';
import { GroupEditionMarkings_group$data } from './__generated__/GroupEditionMarkings_group.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  list: {
    width: '100%',
    maxWidth: 360,
    backgroundColor: theme.palette.background.paper,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
}));

const groupMutationRelationAdd = graphql`
  mutation GroupEditionMarkingsMarkingDefinitionsRelationAddMutation(
    $id: ID!
    $input: InternalRelationshipAddInput!
  ) {
    groupEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...GroupEditionMarkings_group
        }
      }
    }
  }
`;

const groupMutationRelationDelete = graphql`
  mutation GroupEditionMarkingsMarkingDefinitionsRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    groupEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...GroupEditionMarkings_group
      }
    }
  }
`;

const GroupEditionMarkingsComponent = ({ group }: { group: GroupEditionMarkings_group$data }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const groupMarkingDefinitions = (group.allowed_marking || []) as { id : string }[];
  const [commitAdd] = useMutation(groupMutationRelationAdd);
  const [commitDelete] = useMutation(groupMutationRelationDelete);

  const handleToggle = (markingDefinitionId: string, groupMarkingDefinition: { id?: string } | undefined, event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.checked) {
      commitAdd({
        variables: {
          id: group.id,
          input: {
            toId: markingDefinitionId,
            relationship_type: 'accesses-to',
          },
        },
      });
    } else if (groupMarkingDefinition !== undefined) {
      commitDelete({
        variables: {
          id: group.id,
          toId: markingDefinitionId,
          relationship_type: 'accesses-to',
        },
      });
    }
  };
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
        render={({ props }: { props: MarkingDefinitionsLinesSearchQuery$data }) => {
          if (props) {
            // Done
            const markingDefinitions = (props.markingDefinitions?.edges ?? []).map((n) => n.node);
            return (
              <List className={classes.root}>
                {markingDefinitions.map((markingDefinition) => {
                  const groupMarkingDefinition = groupMarkingDefinitions.find((g) => g.id === markingDefinition.id);
                  return (
                    <ListItem key={markingDefinition.id} divider={true}>
                      <ListItemIcon color="primary">
                        <CenterFocusStrongOutlined />
                      </ListItemIcon>
                      <ListItemText primary={markingDefinition.definition} />
                      <ListItemSecondaryAction>
                        <Checkbox
                          onChange={(event) => handleToggle(
                            markingDefinition.id,
                            groupMarkingDefinition,
                            event,
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
};

const GroupEditionMarkings = createFragmentContainer(
  GroupEditionMarkingsComponent,
  {
    group: graphql`
      fragment GroupEditionMarkings_group on Group {
        id
        default_assignation
        allowed_marking {
          id
        }
      }
    `,
  },
);

export default GroupEditionMarkings;
