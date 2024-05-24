import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import Checkbox from '@mui/material/Checkbox';
import Alert from '@mui/lab/Alert';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import MarkingsSelectField from '@components/common/form/MarkingsSelectField';
import * as Yup from 'yup';
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
import useApiMutation from '../../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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

const groupMutationFieldPatch = graphql`
    mutation GroupEditionMarkingsMarkingDefinitionsPatchMaxShareableMarkingsIdsMutation(
        $id: ID!
        $input: [EditInput]!
    ) {
        groupEdit(id: $id) {
            fieldPatch(input: $input) {
                ...GroupEditionMarkings_group
            }
        }
    }
`;

const groupMarkingsValidation = () => Yup.object().shape({
  max_shareable_marking_ids: Yup.array().of(Yup.string()).nullable(),
});

const GroupEditionMarkingsComponent = ({
  group,
}: {
  group: GroupEditionMarkings_group$data;
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const groupMarkingDefinitions = group.allowed_marking || [];
  const groupDefaultMarkingDefinitions = group.default_marking || [];
  const groupMaxShareableMarkings = group.max_shareable_marking || [];
  // Handle only GLOBAL entity type for now
  const globalDefaultMarking = (
    groupDefaultMarkingDefinitions.find((e) => e.entity_type === 'GLOBAL')
      ?.values ?? []
  ).filter((v) => groupMarkingDefinitions.map((m) => m.id).includes(v.id));

  const [commitAdd] = useApiMutation(groupMutationRelationAdd);
  const [commitDelete] = useApiMutation(groupMutationRelationDelete);
  const [commitDefaultValues] = useApiMutation(groupMutationPatchDefaultValues);
  const [commitFieldPatch] = useApiMutation(groupMutationFieldPatch);

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
        commitDefaultValues({
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
    commitDefaultValues({
      variables: {
        id: group.id,
        input: {
          entity_type: 'GLOBAL',
          values: ids,
        },
      },
    });
  };

  const handleToggleMarkingIds = (name: string, markingIds: string[]) => {
    groupMarkingsValidation()
      .validateAt(name, { [name]: markingIds })
      .then(() => {
        commitFieldPatch({
          variables: {
            id: group.id,
            input: {
              key: name,
              value: markingIds,
            },
          },
        });
      })
      .catch(() => false);
  };

  const retrieveMarking = (
    markingIds: readonly { readonly id: string }[] | null,
    markingDefinitions: Option[],
  ) => {
    return markingIds?.map((g) => markingDefinitions.find((m) => m.value === g.id));
  };

  return (
    <div>
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
                <Typography variant="h2" style={{ marginTop: 35 }}>
                  {t_i18n('Allowed marking definitions')}
                </Typography>
                <Alert severity="warning" variant="outlined" style={{ marginBottom: 10 }}>
                  {t_i18n(
                    'All users of this group will be able to view entities and relationships marked with checked marking definitions, including statements and special markings.',
                  )}
                </Alert>
                <List>
                  {markingDefinitions.map((markingDefinition) => {
                    const groupMarkingDefinition = groupMarkingDefinitions.find(
                      (g) => markingDefinition.id === g.id,
                    );
                    return (
                      <ListItem key={markingDefinition.id} divider={true}>
                        <ListItemIcon>
                          <ItemIcon
                            type="Marking-Definition"
                            color={markingDefinition.x_opencti_color ?? undefined}
                          />
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
                <Formik
                  enableReinitialize={true}
                  initialValues={{
                    defaultMarkings: resolvedGroupDefaultMarkingDefinitions,
                    shareableMarkings: groupMaxShareableMarkings.map((v) => v.id),
                  }}
                  onSubmit={() => {}}
                >
                  {() => (
                    <Form>
                      <Typography variant="h2" style={{ marginTop: 30 }}>
                        {t_i18n('Default marking definitions')}
                      </Typography>
                      <Alert
                        severity="info"
                        variant="outlined"
                        style={{ marginBottom: 10 }}
                      >
                        {t_i18n(
                          'The default marking definitions of a group will be used as default marking when this feature is explicitly enabled in the customization of an entity type.',
                        )}
                        <br />
                        <br />
                        {t_i18n(
                          'Please note that only the marking definition with the highest level on each definition type is kept.',
                        )}
                      </Alert>
                      <Field
                        component={AutocompleteField}
                        style={fieldSpacingContainerStyle}
                        name={'defaultMarkings'}
                        multiple={true}
                        textfieldprops={{
                          variant: 'standard',
                          label: t_i18n('Default markings'),
                        }}
                        noOptionsText={t_i18n('No available options')}
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
                      <Typography variant="h2" style={{ marginTop: 30 }}>
                        {t_i18n('Maximum shareable marking definitions')}
                      </Typography>
                      <Alert
                        severity="info"
                        variant="outlined"
                        style={{ marginBottom: 10 }}
                      >
                        {t_i18n(
                          'The maximum shareable marking definitions of a group are the maximum markings authorized in shared public dashboards and file exports.',
                        )}
                      </Alert>
                      <Field
                        component={MarkingsSelectField}
                        markingDefinitions={(resolvedGroupMarkingDefinitions ?? []).map((m) => m?.entity)}
                        name="shareableMarkings"
                        onChange={(markingIds: string[]) => handleToggleMarkingIds('max_shareable_marking_ids', markingIds)}
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
        max_shareable_marking {
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
