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
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { markingDefinitionsLinesSearchQuery } from '../marking_definitions/MarkingDefinitionsLines';
import { MarkingDefinitionsLinesSearchQuery$data } from '../marking_definitions/__generated__/MarkingDefinitionsLinesSearchQuery.graphql';
import { GroupEditionMarkings_group$data } from './__generated__/GroupEditionMarkings_group.graphql';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';
import { Option } from '../../common/form/ReferenceField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { convertMarking } from '../../../../utils/edition';

const useStyles = makeStyles({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
});

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

const groupMutationPatchDefaultValues = graphql`
  mutation GroupEditionMarkingsMarkingDefinitionsPatchDefaultValuesMutation(
    $id: ID!
    $input: DefaultMarkingInput!
  ) {
    groupEdit(id: $id) {
      editDefaultMarking(input: $input) {
        ...GroupEditionMarkings_group
      }
    }
  }
`;

const GroupEditionMarkingsComponent = ({
  group,
}: {
  group: GroupEditionMarkings_group$data;
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const groupMarkingDefinitions = group.allowed_marking || [];
  const groupDefaultMarkingDefinitions = group.default_marking || [];
  // Handle only GLOBAL entity type for now
  const globalDefaultMarking = (
    groupDefaultMarkingDefinitions.find((e) => e.entity_type === 'GLOBAL')
      ?.values ?? []
  ).filter((v) => groupMarkingDefinitions.map((m) => m.id).includes(v.id));

  const [commitAdd] = useMutation(groupMutationRelationAdd);
  const [commitDelete] = useMutation(groupMutationRelationDelete);
  const [commitPatch] = useMutation(groupMutationPatchDefaultValues);

  const handleToggle = (
    markingDefinitionId: string,
    groupMarkingDefinition:
    | {
      id?: string;
    }
    | undefined,
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
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
      // Remove default if necessary
      if (globalDefaultMarking.find((m) => m.id === markingDefinitionId)) {
        const ids = globalDefaultMarking
          .map((m) => m.id)
          .filter((id) => id !== markingDefinitionId);
        commitPatch({
          variables: {
            id: group.id,
            input: {
              entity_type: 'GLOBAL',
              values: ids,
            },
          },
        });
      }

      commitDelete({
        variables: {
          id: group.id,
          toId: markingDefinitionId,
          relationship_type: 'accesses-to',
        },
      });
    }
  };
  const handleToggleDefaultValues = (values: Option[]) => {
    const ids = values.map((v) => v.value);
    commitPatch({
      variables: {
        id: group.id,
        input: {
          entity_type: 'GLOBAL',
          values: ids,
        },
      },
    });
  };

  const retrieveMarking = (
    markingIds: readonly { readonly id: string }[] | null,
    markingDefinitions: Option[],
  ) => {
    return markingIds?.map((g) => markingDefinitions.find((m) => m.value === g.id));
  };

  return (
    <div>
      <Typography variant="h2" style={{ marginTop: 35 }}>
        {t('Allowed marking definitions')}
      </Typography>
      <Alert severity="warning" variant="outlined" style={{ marginBottom: 10 }}>
        {t(
          'All users of this group will be able to view entities and relationships marked with checked marking definitions, including statements and special markings.',
        )}
      </Alert>
      <QueryRenderer
        query={markingDefinitionsLinesSearchQuery}
        variables={{ search: '' }}
        render={({
          props,
        }: {
          props: MarkingDefinitionsLinesSearchQuery$data;
        }) => {
          if (props) {
            const markingDefinitions = (
              props.markingDefinitions?.edges ?? []
            ).map((n) => n.node);
            const markingDefinitionsConverted = markingDefinitions.map(convertMarking);
            const resolvedGroupMarkingDefinitions = retrieveMarking(
              groupMarkingDefinitions,
              markingDefinitionsConverted,
            );
            const resolvedGroupDefaultMarkingDefinitions = retrieveMarking(
              globalDefaultMarking,
              markingDefinitionsConverted,
            );
            return (
              <>
                <List>
                  {markingDefinitions.map((markingDefinition) => {
                    const groupMarkingDefinition = groupMarkingDefinitions.find(
                      (g) => markingDefinition.id === g.id,
                    );
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
                            )
                            }
                            checked={groupMarkingDefinition !== undefined}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                    );
                  })}
                </List>
                <Typography variant="h2" style={{ marginTop: 30 }}>
                  {t('Default marking definitions')}
                </Typography>
                <Alert
                  severity="info"
                  variant="outlined"
                  style={{ marginBottom: 10 }}
                >
                  {t(
                    'The default marking definitions of a group will be used as default marking when this feature is explicitly enabled in the customization of an entity type.',
                  )}
                  <br />
                  <br />
                  {t(
                    'Please note that only the marking definition with the highest level on each definition type is kept.',
                  )}
                </Alert>
                <Formik
                  enableReinitialize={true}
                  initialValues={{
                    defaultMarkings: resolvedGroupDefaultMarkingDefinitions,
                  }}
                  onSubmit={() => {}}
                >
                  {() => (
                    <Form>
                      <Field
                        component={AutocompleteField}
                        style={fieldSpacingContainerStyle}
                        name={'defaultMarkings'}
                        multiple={true}
                        textfieldprops={{
                          variant: 'standard',
                          label: t('Default markings'),
                        }}
                        noOptionsText={t('No available options')}
                        options={resolvedGroupMarkingDefinitions}
                        renderOption={(
                          renderProps: React.HTMLAttributes<HTMLLIElement>,
                          option: Option,
                        ) => (
                          <li {...renderProps}>
                            <div
                              className={classes.icon}
                              style={{ color: option.color }}
                            >
                              <ItemIcon
                                type="Marking-Definition"
                                color={option.color}
                              />
                            </div>
                            <div className={classes.text}>{option.label}</div>
                          </li>
                        )}
                        onChange={(name: string, values: Option[]) => handleToggleDefaultValues(values)
                        }
                      />
                    </Form>
                  )}
                </Formik>
              </>
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
        default_marking {
          entity_type
          values {
            id
          }
        }
      }
    `,
  },
);

export default GroupEditionMarkings;
