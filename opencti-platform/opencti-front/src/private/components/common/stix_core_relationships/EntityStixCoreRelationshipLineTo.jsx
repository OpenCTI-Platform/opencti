import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link } from 'react-router';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Box from '@mui/material/Box';
import { MoreVertOutlined } from '@mui/icons-material';
import { AutoFix } from 'mdi-material-ui';
import Skeleton from '@mui/material/Skeleton';
import Tooltip from '@mui/material/Tooltip';
import { ListItemButton } from '@mui/material';
import { styled, useTheme } from '@mui/material/styles';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixCoreRelationshipPopover from './StixCoreRelationshipPopover';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemEntityType from '../../../../components/ItemEntityType';
import { DraftChip, getDraftModeColor } from '../draft/DraftChip';
import SecurityCoverageScores from '../../analyses/security_coverages/security_coverage_scores/SecurityCoverageScores';
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

class EntityStixCoreRelationshipLineToComponent extends Component {
  render() {
    const {
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
    const restricted = node.from === null;
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
            isCoverage={isCoverage}
          />
        )}
      >
        <ListItemButton
          sx={{ paddingLeft: '10px', height: 50 }}
          component={Link}
          to={link}
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
            <ItemIcon type={node.entity_type} color={node.draftVersion ? getDraftModeColor(theme) : null} />
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
                      entityType={node.from?.entity_type}
                      isRestricted={!node.from}
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
                  {!restricted ? getMainRepresentative(node.from) : t('Restricted')}
                  {node.from?.draftVersion && (<DraftChip />)}
                </BodyItem>
                {dataColumns.x_mitre_id && (
                  <BodyItem
                    style={{ width: dataColumns.x_mitre_id.width }}
                  >
                    {node.from?.x_mitre_id ?? EMPTY_VALUE}
                  </BodyItem>
                )}
                {dataColumns.coverage_information && (
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
                {dataColumns.created_at && (
                  <BodyItem
                    style={{ width: dataColumns.created_at.width }}
                  >
                    {fsd(node.created_at)}
                  </BodyItem>
                )}
                {dataColumns.confidence && (
                  <BodyItem
                    style={{ width: dataColumns.confidence.width }}
                  >
                    <ItemConfidence confidence={node.confidence} entityType={node.entity_type} variant="inList" />
                  </BodyItem>
                )}
                {dataColumns.objectMarking && (
                  <BodyItem
                    style={{ width: dataColumns.objectMarking.width }}
                  >
                    <ItemMarkings
                      variant="inList"
                      markingDefinitions={node.objectMarking ?? []}
                      limit={1}
                    />
                  </BodyItem>
                )}
              </Row>
            )}
          />
        </ListItemButton>
      </ListItem>
    );
  }
}

EntityStixCoreRelationshipLineToComponent.propTypes = {
  dataColumns: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  node: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
};

const EntityStixCoreRelationshipLineToFragment = createFragmentContainer(
  EntityStixCoreRelationshipLineToComponent,
  {
    node: graphql`
      fragment EntityStixCoreRelationshipLineTo_node on StixCoreRelationship {
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
        coverage_information {
          coverage_name
          coverage_score
        }
        created_at
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
          ... on AttackPattern {
            name
            description
            x_mitre_id
            killChainPhases {
              id
              phase_name
              x_opencti_order
            }
          }
          ... on Campaign {
            name
            description
          }
          ... on CourseOfAction {
            name
            description
          }
          ... on Individual {
            name
            description
          }
          ... on Organization {
            name
            description
          }
          ... on Sector {
            name
            description
          }
          ... on System {
            name
            description
          }
          ... on Indicator {
            name
            description
          }
          ... on Infrastructure {
            name
            description
          }
          ... on IntrusionSet {
            name
            description
          }
          ... on Position {
            name
            description
          }
          ... on City {
            name
            description
          }
          ... on AdministrativeArea {
            name
            description
          }
          ... on Country {
            name
            description
          }
          ... on Region {
            name
            description
          }
          ... on Malware {
            name
            description
          }
          ... on MalwareAnalysis {
            result_name
          }
          ... on ThreatActor {
            name
            description
          }
          ... on Tool {
            name
            description
          }
          ... on Vulnerability {
            name
            description
          }
          ... on Incident {
            name
            description
          }
          ... on Event {
            name
            description
          }
          ... on Channel {
            name
            description
          }
          ... on Narrative {
            name
            description
          }
          ... on Language {
            name
          }
          ... on DataComponent {
            name
          }
          ... on DataSource {
            name
          }
          ... on Case {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
          ... on Indicator {
            name
            pattern_type
            pattern_version
            description
            valid_from
            valid_until
            x_opencti_score
            x_opencti_main_observable_type
          }
          ... on ObservedData {
            name
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
            parent_types
            created_at
            updated_at
          }
          ... on StixDomainObject {
            created
            modified
          }
          ... on AttackPattern {
            name
            description
            x_mitre_id
          }
          ... on Campaign {
            name
            description
          }
          ... on CourseOfAction {
            name
            description
          }
          ... on Individual {
            name
            description
          }
          ... on Organization {
            name
            description
          }
          ... on Sector {
            name
            description
          }
          ... on System {
            name
            description
          }
          ... on Indicator {
            name
            description
          }
          ... on Infrastructure {
            name
            description
          }
          ... on IntrusionSet {
            name
            description
          }
          ... on Position {
            name
            description
          }
          ... on City {
            name
            description
          }
          ... on AdministrativeArea {
            name
            description
          }
          ... on Country {
            name
            description
          }
          ... on Region {
            name
            description
          }
          ... on Malware {
            name
            description
          }
          ... on MalwareAnalysis {
            result_name
          }
          ... on ThreatActor {
            name
            description
          }
          ... on Tool {
            name
            description
          }
          ... on Vulnerability {
            name
            description
          }
          ... on Incident {
            name
            description
          }
          ... on Event {
            name
            description
          }
          ... on Channel {
            name
            description
          }
          ... on Narrative {
            name
            description
          }
          ... on Language {
            name
          }
          ... on DataComponent {
            name
          }
          ... on DataSource {
            name
          }
          ... on Case {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
          ... on Indicator {
            name
            pattern_type
            pattern_version
            description
            valid_from
            valid_until
            x_opencti_score
            x_opencti_main_observable_type
          }
          ... on ObservedData {
            name
          }
        }
      }
    `,
  },
);

const EntityStixCoreRelationshipLineToWithTheme = (props) => {
  const theme = useTheme();
  return <EntityStixCoreRelationshipLineToFragment {...props} theme={theme} />;
};

export const EntityStixCoreRelationshipLineTo = inject18n(EntityStixCoreRelationshipLineToWithTheme);

class EntityStixCoreRelationshipLineToDummyComponent extends Component {
  render() {
    const { dataColumns } = this.props;
    return (
      <ListItem
        sx={{ paddingLeft: '10px', height: 50 }}
        divider={true}
        secondaryAction={(
          <Box>
            <MoreVertOutlined />
          </Box>
        )}
      >
        <ListItemIcon
          sx={{ color: (theme) => theme.palette.grey[700] }}
          style={{ minWidth: 40 }}
        >
          <Checkbox
            disabled={true}
          />
        </ListItemIcon>
        <ListItemIcon sx={{ color: (theme) => theme.palette.primary.main }}>
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

EntityStixCoreRelationshipLineToDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
};

export const EntityStixCoreRelationshipLineToDummy = inject18n(EntityStixCoreRelationshipLineToDummyComponent);
