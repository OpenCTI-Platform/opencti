import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link } from 'react-router';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVertOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { AutoFix } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { styled } from '@mui/material/styles';
import { ListItemButton } from '@mui/material';
import inject18n from '../../../../components/i18n';
import withTheme from '../../../../components/withTheme';
import ItemIcon from '../../../../components/ItemIcon';
import SecurityCoverageScores from '../../analyses/security_coverages/security_coverage_scores/SecurityCoverageScores';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixCoreRelationshipPopover from './StixCoreRelationshipPopover';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemEntityType from '../../../../components/ItemEntityType';
import { DraftChip, getDraftModeColor } from '../draft/DraftChip';
import { EMPTY_VALUE } from '../../../../utils/String';
import { Checkbox } from '@filigran/design-system';

const Row = styled('div')({
  display: 'flex',
  alignItems: 'center',
  height: '100%',
  width: '100%',
});

const BodyItem = styled('div')({
  height: '100%',
  fontSize: 13,
  display: 'flex',
  alignItems: 'center',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: 10,
});

class EntityStixCoreRelationshipLineAllComponent extends Component {
  render() {
    const {
      entityId,
      fsd,
      t,
      theme,
      dataColumns,
      node,
      paginationOptions,
      entityLink,
      onToggleEntity,
      selectAll,
      deSelectedElements,
      selectedElements,
      onToggleShiftEntity,
      index,
      isCoverage,
    } = this.props;
    const remoteNode = node.from && node.from.id === entityId ? node.to : node.from;
    const isReversed = node.from && node.from.id === entityId;
    const restricted = node.from === null || node.to === null;
    const link = `${entityLink}/relations/${node.id}`;
    return (
      <ListItem
        divider={true}
        disablePadding
        secondaryAction={node.is_inferred ? (
          <Tooltip
            title={
              t('Inferred knowledge based on the rule ')
              + R.head(node.x_opencti_inferences).rule.name
            }
          >
            <AutoFix fontSize="small" style={{ marginLeft: -30 }} />
          </Tooltip>
        ) : (
          <StixCoreRelationshipPopover
            stixCoreRelationshipId={node.id}
            paginationOptions={paginationOptions}
            disabled={restricted}
            isCoverage={isCoverage}
          />
        )}
      >
        <ListItemButton
          sx={{ paddingLeft: '10px', height: 50 }}
          component={Link}
          to={link}
          disabled={restricted}
        >
          <ListItemIcon
            sx={{ color: theme.palette.primary.main }}
            style={{ minWidth: 40 }}
            onClick={(event) => (event.shiftKey
              ? onToggleShiftEntity(index, node)
              : onToggleEntity(node, event))
            }
          >
            <Checkbox
              checked={
                (selectAll && !(node.id in (deSelectedElements || {})))
                || node.id in (selectedElements || {})
              }
            />
          </ListItemIcon>
          <ListItemIcon sx={{ color: theme.palette.primary.main }}>
            <ItemIcon type={node.entity_type} isReversed={isReversed} color={node.draftVersion ? getDraftModeColor(theme) : null} />
          </ListItemIcon>
          <ListItemText
            sx={{ margin: 0 }}
            primary={(
              <Row>
                {dataColumns.relationship_type && (
                  <BodyItem
                    style={{ width: dataColumns.relationship_type.width }}
                  >
                    <ItemEntityType
                      entityType={node.relationship_type}
                    />
                  </BodyItem>
                )}
                {dataColumns.entity_type && (
                  <BodyItem
                    style={{ width: dataColumns.entity_type.width }}
                  >
                    <ItemEntityType
                      entityType={remoteNode.entity_type}
                      isRestricted={restricted}
                      size="large"
                      showIcon
                    />
                  </BodyItem>
                )}
                <BodyItem
                  style={{
                    width: dataColumns.name
                      ? dataColumns.name.width
                      : dataColumns.observable_value.width,
                  }}
                >
                  {!restricted ? getMainRepresentative(remoteNode) : t('Restricted')}
                  {remoteNode.draftVersion && (<DraftChip />)}
                </BodyItem>
                {isCoverage && dataColumns.coverage_information && (
                  <BodyItem
                    style={{
                      width: dataColumns.coverage_information.width,
                      display: 'flex',
                      alignItems: 'center',
                      height: 'auto',
                      overflow: 'visible',
                    }}
                  >
                    <SecurityCoverageScores
                      coverage_information={node.coverage_information || null}
                      variant="header"
                    />
                  </BodyItem>
                )}
                <BodyItem
                  style={{ width: dataColumns.createdBy.width }}
                >
                  {node.createdBy?.name ?? EMPTY_VALUE}
                </BodyItem>
                <BodyItem
                  style={{ width: dataColumns.creator.width }}
                >
                  {(node.creators ?? []).map((c) => c?.name).join(', ')}
                </BodyItem>
                <BodyItem
                  style={{ width: dataColumns.start_time.width }}
                >
                  {fsd(node.start_time)}
                </BodyItem>
                <BodyItem
                  style={{ width: dataColumns.stop_time.width }}
                >
                  {fsd(node.stop_time)}
                </BodyItem>
                {!isCoverage && dataColumns.created_at && (
                  <BodyItem
                    style={{ width: dataColumns.created_at.width }}
                  >
                    {fsd(node.created_at)}
                  </BodyItem>
                )}
                <BodyItem
                  style={{ width: dataColumns.confidence.width }}
                >
                  <ItemConfidence confidence={node.confidence} entityType={node.entity_type} variant="inList" />
                </BodyItem>
                <BodyItem
                  style={{ width: dataColumns.objectMarking.width }}
                >
                  <ItemMarkings
                    variant="inList"
                    markingDefinitions={node.objectMarking ?? []}
                    limit={1}
                  />
                </BodyItem>
              </Row>
            )}
          />
        </ListItemButton>
      </ListItem>
    );
  }
}

EntityStixCoreRelationshipLineAllComponent.propTypes = {
  dataColumns: PropTypes.object,
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  node: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
};

const EntityStixCoreRelationshipLineAllFragment = createFragmentContainer(
  EntityStixCoreRelationshipLineAllComponent,
  {
    node: graphql`
      fragment EntityStixCoreRelationshipLineAll_node on StixCoreRelationship {
        id
        draftVersion {
          draft_id
          draft_operation
        }
        entity_type
        parent_types
        relationship_type
        confidence
        start_time
        stop_time
        description
        is_inferred
        created
        created_at
        coverage_information {
          coverage_name
          coverage_score
        }
        x_opencti_inferences {
          rule {
            id
            name
          }
        }
        createdBy {
          ... on Identity {
            name
          }
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        creators {
          id
          name
        }
        killChainPhases {
          id
          phase_name
          x_opencti_order
        }
        from {
          ... on StixCoreObject {
            id
            draftVersion {
              draft_id
              draft_operation
            }
            entity_type
            representative {
              main
            }
            parent_types
            created_at
            updated_at
            objectLabel {
              id
              value
              color
            }
            createdBy {
              ... on Identity {
                name
              }
            }
            objectMarking {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
            creators {
              id
              name
            }
          }
          ... on StixDomainObject {
            created
            modified
          }
          ... on StixCoreRelationship {
            id
            entity_type
            parent_types
            created
            created_at
            from {
              ... on StixCoreObject {
                id
                entity_type
                representative {
                  main
                }
                parent_types
                created_at
                updated_at
                objectLabel {
                  id
                  value
                  color
                }
                createdBy {
                  ... on Identity {
                    name
                  }
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
                creators {
                  id
                  name
                }
              }
              ... on StixDomainObject {
                created
                modified
              }
              ... on StixCoreRelationship {
                id
                entity_type
                parent_types
                created
                created_at
              }
            }
            to {
              ... on StixCoreObject {
                id
                entity_type
                representative {
                  main
                }
                parent_types
                created_at
                updated_at
                objectLabel {
                  id
                  value
                  color
                }
                createdBy {
                  ... on Identity {
                    name
                  }
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
                creators {
                  id
                  name
                }
              }
              ... on StixDomainObject {
                created
                modified
              }
              ... on StixCoreRelationship {
                id
                entity_type
                created
                created_at
                parent_types
              }
            }
          }
        }
        to {
          ... on StixCoreObject {
            id
            draftVersion {
              draft_id
              draft_operation
            }
            entity_type
            representative {
              main
            }
            parent_types
            created_at
            updated_at
            objectLabel {
              id
              value
              color
            }
            createdBy {
              ... on Identity {
                name
              }
            }
            objectMarking {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
            creators {
              id
              name
            }
          }
          ... on StixDomainObject {
            created
            modified
          }
          ... on StixCoreRelationship {
            id
            entity_type
            created
            created_at
            parent_types
            from {
              ... on StixCoreObject {
                id
                entity_type
                representative {
                  main
                }
                parent_types
                created_at
                updated_at
                objectLabel {
                  id
                  value
                  color
                }
                createdBy {
                  ... on Identity {
                    name
                  }
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
                creators {
                  id
                  name
                }
              }
              ... on StixDomainObject {
                created
                modified
              }
              ... on StixCoreRelationship {
                id
                entity_type
                parent_types
                created
                created_at
              }
            }
            to {
              ... on StixCoreObject {
                id
                entity_type
                representative {
                  main
                }
                parent_types
                created_at
                updated_at
                objectLabel {
                  id
                  value
                  color
                }
                createdBy {
                  ... on Identity {
                    name
                  }
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
                creators {
                  id
                  name
                }
              }
              ... on StixDomainObject {
                created
                modified
              }
              ... on StixCoreRelationship {
                id
                entity_type
                created
                created_at
                parent_types
              }
            }
          }
        }
      }
    `,
  },
);

export const EntityStixCoreRelationshipLineAll = inject18n(withTheme(EntityStixCoreRelationshipLineAllFragment));

class EntityStixCoreRelationshipLineAllDummyComponent extends Component {
  render() {
    const { dataColumns } = this.props;
    return (
      <ListItem
        sx={{ paddingLeft: '10px', height: 50 }}
        divider={true}
        secondaryAction={<MoreVertOutlined />}
      >
        <ListItemIcon
          sx={{ color: 'grey.700' }}
          style={{ minWidth: 40 }}
        >
          <Checkbox
            disabled={true}
          />
        </ListItemIcon>
        <ListItemIcon sx={{ color: 'primary.main' }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          sx={{ margin: 0 }}
          primary={(
            <Row>
              {dataColumns.relationship_type && (
                <BodyItem
                  style={{ width: dataColumns.relationship_type.width }}
                >
                  <Skeleton
                    animation="wave"
                    variant="rectangular"
                    width="90%"
                    height="100%"
                  />
                </BodyItem>
              )}
              {dataColumns.entity_type && (
                <BodyItem
                  style={{ width: dataColumns.entity_type.width }}
                >
                  <Skeleton
                    animation="wave"
                    variant="rectangular"
                    width="90%"
                    height="100%"
                  />
                </BodyItem>
              )}
              <BodyItem
                style={{
                  width: dataColumns.name
                    ? dataColumns.name.width
                    : dataColumns.observable_value?.width,
                }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
              {dataColumns.x_mitre_id && (
                <BodyItem
                  style={{ width: dataColumns.x_mitre_id.width }}
                >
                  <Skeleton
                    animation="wave"
                    variant="rectangular"
                    width="90%"
                    height="100%"
                  />
                </BodyItem>
              )}
              {dataColumns.coverage_information && (
                <BodyItem
                  style={{ width: dataColumns.coverage_information.width }}
                >
                  <Skeleton
                    animation="wave"
                    variant="rectangular"
                    width="90%"
                    height="100%"
                  />
                </BodyItem>
              )}
              <BodyItem
                style={{ width: dataColumns.createdBy.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.creator.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.start_time.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={140}
                  height="100%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.stop_time.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={140}
                  height="100%"
                />
              </BodyItem>
              {dataColumns.created_at && (
                <BodyItem
                  style={{ width: dataColumns.created_at.width }}
                >
                  <Skeleton
                    animation="wave"
                    variant="rectangular"
                    width={140}
                    height="100%"
                  />
                </BodyItem>
              )}
              {dataColumns.confidence && (
                <BodyItem
                  style={{ width: dataColumns.confidence.width }}
                >
                  <Skeleton
                    animation="wave"
                    variant="rectangular"
                    width={100}
                    height="100%"
                  />
                </BodyItem>
              )}
              {dataColumns.objectMarking && (
                <BodyItem
                  style={{ width: dataColumns.objectMarking.width }}
                >
                  <Skeleton
                    animation="wave"
                    variant="rectangular"
                    width={100}
                    height="100%"
                  />
                </BodyItem>
              )}
            </Row>
          )}
        />
      </ListItem>
    );
  }
}

EntityStixCoreRelationshipLineAllDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
};

export const EntityStixCoreRelationshipLineAllDummy = inject18n(EntityStixCoreRelationshipLineAllDummyComponent);
