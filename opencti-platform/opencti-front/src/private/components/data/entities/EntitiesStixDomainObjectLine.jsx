import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { Link } from 'react-router';
import { KeyboardArrowRight } from '@mui/icons-material';
import { ListItemButton } from '@mui/material';
import { styled } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { resolveLink } from '../../../../utils/Entity';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemEntityType from '../../../../components/ItemEntityType';
import { EMPTY_VALUE } from '../../../../utils/String';
import { Checkbox } from '@filigran/design-system';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

const EntitiesStixDomainObjectLineComponent = ({
  dataColumns,
  node,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleShiftEntity,
  index,
}) => {
  const { fd } = useFormatter();
  const link = `${resolveLink(node.entity_type)}/${node.id}`;
  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      component={Link}
      to={link}
    >
      <ListItemIcon
        sx={{ color: (theme) => theme.palette.primary.main }}
        style={{ minWidth: 40 }}
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, node, event)
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
      <ListItemIcon sx={{ color: (theme) => theme.palette.primary.main }}>
        <ItemIcon type={node.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.entity_type.width }}
            >
              <ItemEntityType entityType={node.entity_type} />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.name.width }}
            >
              {getMainRepresentative(node)}
            </BodyItem>
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
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={node.objectLabel}
                onClick={onLabelClick}
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.created_at.width }}
            >
              {fd(node.created_at)}
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
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRight />
      </ListItemIcon>
    </ListItemButton>
  );
};

export const entitiesFragment = graphql`
  fragment EntitiesStixDomainObjectLine_node on StixDomainObject {
    id
    entity_type
    created_at
    draftVersion {
      draft_id
      draft_operation
    }
    ... on AttackPattern {
      name
      description
      aliases
    }
    ... on Campaign {
      name
      description
      aliases
    }
    ... on Note {
      attribute_abstract
      content
    }
    ... on ObservedData {
      name
      first_observed
      last_observed
    }
    ... on Opinion {
      opinion
      explanation
    }
    ... on Report {
      name
      description
    }
    ... on Grouping {
      name
      description
    }
    ... on SecurityCoverage {
      name
      description
    }
    ... on SecurityCoverageResult {
      name
      description
      resultOf {
        id
      }
    }
    ... on CourseOfAction {
      name
      description
      x_opencti_aliases
    }
    ... on DataComponent {
      name
      aliases
      description
    }
    ... on DataSource {
      name
      aliases
      description
    }
    ... on Case {
      name
      description
    }
    ... on Task {
      name
      description
    }
    ... on Individual {
      name
      description
      x_opencti_aliases
    }
    ... on Organization {
      name
      description
      x_opencti_aliases
    }
    ... on SecurityPlatform {
      name
      description
      security_platform_type
    }
    ... on Sector {
      name
      description
      x_opencti_aliases
    }
    ... on System {
      name
      description
      x_opencti_aliases
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
      aliases
      description
    }
    ... on Position {
      name
      description
      x_opencti_aliases
    }
    ... on City {
      name
      description
      x_opencti_aliases
    }
    ... on AdministrativeArea {
      name
      description
      x_opencti_aliases
    }
    ... on Country {
      name
      description
      x_opencti_aliases
    }
    ... on Region {
      name
      description
      x_opencti_aliases
    }
    ... on Malware {
      name
      aliases
      description
    }
    ... on MalwareAnalysis {
      result_name
    }
    ... on ThreatActor {
      name
      aliases
      description
    }
    ... on Tool {
      name
      aliases
      description
    }
    ... on Vulnerability {
      name
      description
    }
    ... on Incident {
      name
      aliases
      description
    }
    ... on Event {
      name
      description
      aliases
    }
    ... on Channel {
      name
      description
      aliases
    }
    ... on Narrative {
      name
      description
      aliases
    }
    ... on Language {
      name
      aliases
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
    ... on Task {
      name
    }
    createdBy {
      ... on Identity {
        name
      }
    }
    objectMarking {
      
          id
          definition
          x_opencti_order
          x_opencti_color
        
    }
    objectLabel {
      
          id
          value
          color
        
    }
    creators {
      id
      name
    }
  }
`;

export const EntitiesStixDomainObjectLine = createFragmentContainer(
  EntitiesStixDomainObjectLineComponent,
  {
    node: entitiesFragment,
  },
);

export const EntitiesStixDomainObjectLineDummy = ({ dataColumns }) => {
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      style={{ minWidth: 40 }}
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
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
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
            <BodyItem
              style={{ width: dataColumns.name.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
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
              style={{ width: dataColumns.objectLabel.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
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
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRight />
      </ListItemIcon>
    </ListItem>
  );
};
