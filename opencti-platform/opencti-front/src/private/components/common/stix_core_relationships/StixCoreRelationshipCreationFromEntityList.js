import React, { useState } from 'react';
import { CheckCircle } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { graphql } from 'react-relay';
import Skeleton from '@mui/material/Skeleton';
import * as R from 'ramda';
import ItemIcon from '../../../../components/ItemIcon';
import { deleteNodeFromEdge } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference, useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import StixCoreRelationshipCreationForm, { stixCoreRelationshipBasicShape } from './StixCoreRelationshipCreationForm';
import { formatDate } from '../../../../utils/Time';
import { APP_BASE_PATH } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  icon: {
    color: theme.palette.primary.main,
  },
}));

const stixCoreRelationshipCreationFromEntityListRelationAdd = graphql`
  mutation StixCoreRelationshipCreationFromEntityListRelationAddMutation(
    $input: StixCoreRelationshipAddInput
  ) {
    stixCoreRelationshipAdd(input: $input) {
      from {
        ... on CourseOfAction {
          id
          attackPatterns {
            edges {
              node {
                id
                entity_type
                name
                description
              }
            }
          }
        }
        ... on IntrusionSet {
          id
          locations {
            edges {
              node {
                id
                entity_type
                name
                parent_types
                x_opencti_aliases
                description
              }
            }
          }
        }
        ... on ThreatActorIndividual {
          id
          locations {
            edges {
              types
              node {
                id
                entity_type
                name
                parent_types
                x_opencti_aliases
                description
              }
            }
          }
        }
        ... on ThreatActorGroup {
          id
          locations {
            edges {
              types
              node {
                id
                entity_type
                name
                parent_types
                x_opencti_aliases
                description
              }
            }
          }
        }
        ... on DataComponent {
          id
          attackPatterns {
            edges {
              node {
                id
                entity_type
                parent_types
                name
                description
              }
            }
          }
        }
      }
      to {
        ... on AttackPattern {
          id
          subAttackPatterns {
            edges {
              node {
                id
                entity_type
                name
                description
                x_mitre_id
              }
            }
          }
          coursesOfAction {
            edges {
              node {
                id
                entity_type
                name
                description
              }
            }
          }
          dataComponents {
            edges {
              node {
                id
                entity_type
                name
                description
              }
            }
          }
        }
        ... on Sector {
          id
          subSectors {
            edges {
              types
              node {
                id
                entity_type
                name
                description
              }
            }
          }
        }
        ... on Narrative {
          id
          subNarratives {
            edges {
              node {
                id
                entity_type
                name
                description
              }
            }
          }
        }
        ... on Vulnerability {
          ...VulnerabilitySoftwares_vulnerability
        }
        ... on StixCyberObservable {
          ...StixCyberObservableIndicators_stixCyberObservable
        }
      }
    }
  }
`;

const stixCoreRelationshipCreationFromEntityListRelationDelete = graphql`
  mutation StixCoreRelationshipCreationFromEntityListRelationDeleteMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
    )
  }
`;

const StixCoreRelationshipCreationFromEntityDummyList = () => {
  return (
    <List>
      {Array.from(Array(20), (e, i) => (
        <ListItem key={i} divider={true} button={false}>
          <ListItemIcon>
            <Skeleton
              animation="wave"
              variant="circular"
              width={30}
              height={30}
            />
          </ListItemIcon>
          <ListItemText
            primary={
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height={15}
                style={{ marginBottom: 10 }}
              />
            }
            secondary={
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height={15}
              />
            }
          />
        </ListItem>
      ))}
    </List>
  );
};

const StixCoreRelationshipCreationFromEntityList = ({
  entity,
  relationshipType,
  availableDatas,
  existingDatas,
  updaterOptions,
  isRelationReversed,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const [commitRelationAdd] = useApiMutation(
    stixCoreRelationshipCreationFromEntityListRelationAdd,
  );
  const [commitRelationDelete] = useApiMutation(
    stixCoreRelationshipCreationFromEntityListRelationDelete,
  );

  const enableReferences = useIsEnforceReference('stix-core-relationship');
  const stixCoreRelationshipValidator = useSchemaCreationValidation(
    'stix-core-relationship',
    stixCoreRelationshipBasicShape(t_i18n),
  );
  const [showForm, setShowForm] = useState(false);
  const [selected, setSelected] = useState(null);

  const handleOpenForm = () => {
    setShowForm(true);
  };
  const handleCloseForm = () => {
    setShowForm(false);
  };

  const buildInput = (data) => {
    const from = isRelationReversed ? data.id : entity.id;
    const to = isRelationReversed ? entity.id : data.id;
    return {
      fromId: from,
      toId: to,
      relationship_type: relationshipType,
    };
  };

  const toggle = (data, alreadyAdded) => {
    const input = buildInput(data);
    // Delete
    if (alreadyAdded) {
      commitRelationDelete({
        variables: { ...input },
        updater: (store) => deleteNodeFromEdge(
          store,
          updaterOptions.path,
          entity.id,
          data.id,
          updaterOptions.params,
        ),
      });
      // Add with references
    } else if (
      enableReferences
      || !stixCoreRelationshipValidator.isValidSync(input)
    ) {
      handleOpenForm();
      setSelected(data);
      // Add
    } else {
      commitRelationAdd({
        variables: { input },
      });
    }
  };

  const createRelation = (values) => {
    const input = {
      ...values,
      ...buildInput(selected),
    };
    const finalValues = R.pipe(
      R.assoc('confidence', parseInt(input.confidence, 10)),
      R.assoc('start_time', formatDate(input.start_time)),
      R.assoc('stop_time', formatDate(input.stop_time)),
      R.assoc('killChainPhases', R.pluck('value', input.killChainPhases)),
      R.assoc('createdBy', input.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', input.objectMarking)),
      R.assoc('externalReferences', R.pluck('value', input.externalReferences)),
    )(input);
    commitRelationAdd({
      variables: { input: finalValues },
    });
    handleCloseForm();
  };

  if (!availableDatas) {
    return <StixCoreRelationshipCreationFromEntityDummyList />;
  }

  const existingIds = existingDatas?.map((n) => n.node.id) ?? [];
  const nodes = availableDatas.edges
    .filter((edge) => edge.node.id !== entity.id)
    .map((edge) => edge.node);

  const defaultDescription = (data) => (data.parent_types.includes('Stix-Cyber-Observable')
    ? data.x_opencti_description
    : data.description);

  return (
    <>
      {showForm ? (
        <StixCoreRelationshipCreationForm
          fromEntities={[entity]}
          toEntities={[selected]}
          relationshipTypes={[relationshipType]}
          onSubmit={createRelation}
          handleClose={handleCloseForm}
        />
      ) : (
        <div>
          {nodes.length > 0 ? (
            <List>
              {availableDatas.edges
                .filter((edge) => edge.node.id !== entity.id)
                .map((edge) => {
                  const { node } = edge;
                  const alreadyAdded = existingIds.includes(node.id);
                  const flag = node.entity_type === 'Country'
                    && R.head(
                      (node.x_opencti_aliases ?? []).filter(
                        (n) => n?.length === 2,
                      ),
                    );
                  return (
                    <ListItem
                      key={node.id}
                      divider={true}
                      button={true}
                      onClick={() => toggle(node, alreadyAdded)}
                    >
                      <ListItemIcon>
                        {alreadyAdded ? (
                          <CheckCircle classes={{ root: classes.icon }} />
                        ) : (
                          <>
                            {flag ? (
                              <img
                                style={{ width: 20 }}
                                src={`${APP_BASE_PATH}/static/flags/4x3/${flag.toLowerCase()}.svg`}
                                alt={node.name}
                              />
                            ) : (
                              <ItemIcon type={node.entity_type} />
                            )}
                          </>
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={node.name}
                        secondary={defaultDescription(node)}
                        sx={{
                          '.MuiListItemText-primary, .MuiListItemText-secondary': {
                            overflowX: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            marginRight: '20px',
                          },
                        }}
                      />
                    </ListItem>
                  );
                })}
            </List>
          ) : (
            <div style={{ padding: 20 }}>
              {t_i18n('No entities were found for this search.')}
            </div>
          )}
        </div>
      )}
    </>
  );
};

export default StixCoreRelationshipCreationFromEntityList;
