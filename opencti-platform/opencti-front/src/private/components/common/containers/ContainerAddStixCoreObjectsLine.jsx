import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { CircleOutlined } from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { ListItemButton } from '@mui/material';
import { Checkbox } from '@filigran/design-system';
import { DraftChip } from '../draft/DraftChip';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import ItemMarkings from '../../../../components/ItemMarkings';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemEntityType from '../../../../components/ItemEntityType';
import { EMPTY_VALUE } from '../../../../utils/String';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

const ContainerAddStixCoreObjectsLineComponent = ({
  dataColumns,
  node,
  onLabelClick,
  onToggleEntity,
  addedElements,
}) => {
  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      onClick={(event) => onToggleEntity(node, event)}
    >
      <ListItemIcon style={{ paddingLeft: 10 }}>
        <Checkbox checked={node.id in (addedElements || {})} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.entity_type.width }}
            >
              <ItemEntityType showIcon entityType={node.entity_type} />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.value.width }}
            >
              {getMainRepresentative(node)}
              {node.draftVersion && (<DraftChip />)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.createdBy.width }}
            >
              {node.createdBy?.name ?? EMPTY_VALUE}
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
    </ListItemButton>
  );
};

export const ContainerAddStixCoreObjectsLine = createFragmentContainer(
  ContainerAddStixCoreObjectsLineComponent,
  {
    node: graphql`
      fragment ContainerAddStixCoreObjectsLine_node on StixCoreObject {
        id
        draftVersion {
          draft_id
          draft_operation
        }
        standard_id
        parent_types
        entity_type
        representative {
          main
        }
        created_at
        ... on AttackPattern {
          name
        }
        ... on Campaign {
          name
        }
        ... on Note {
          attribute_abstract
        }
        ... on ObservedData {
          name
        }
        ... on Opinion {
          opinion
        }
        ... on Report {
          name
        }
        ... on Grouping {
          name
        }
        ... on CourseOfAction {
          name
        }
        ... on Individual {
          name
        }
        ... on Organization {
          name
        }
        ... on Sector {
          name
        }
        ... on System {
          name
        }
        ... on Indicator {
          name
        }
        ... on Infrastructure {
          name
        }
        ... on IntrusionSet {
          name
        }
        ... on Position {
          name
        }
        ... on City {
          name
        }
        ... on AdministrativeArea {
          name
        }
        ... on Country {
          name
        }
        ... on Region {
          name
        }
        ... on Malware {
          name
        }
        ... on MalwareAnalysis {
          result_name
        }
        ... on ThreatActor {
          name
        }
        ... on Tool {
          name
        }
        ... on Vulnerability {
          name
        }
        ... on Incident {
          name
        }
        ... on Event {
          name
        }
        ... on Channel {
          name
        }
        ... on Narrative {
          name
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
          ... on StixFile {
            hashes {
              algorithm
              hash
            }
          }
        }
        createdBy {
          id
          entity_type
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
    `,
  },
);

export const ContainerAddStixCoreObjecstLineDummy = ({ dataColumns }) => {
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      style={{ minWidth: 40, paddingLeft: 20 }}
    >
      <ListItemIcon
        sx={{ color: 'grey.700' }}
        style={{ minWidth: 44 }}
      >
        <CircleOutlined />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.entity_type.width }}
            >
              <Skeleton
                animation="wave"
                variant="rounded"
                width="100%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.value.width }}
            >
              <Skeleton
                animation="wave"
                variant="rounded"
                width="100%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.createdBy.width }}
            >
              <Skeleton
                animation="wave"
                variant="rounded"
                width="100%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.objectLabel.width }}
            >
              <Skeleton
                animation="wave"
                variant="rounded"
                width="100%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.objectMarking.width }}
            >
              <Skeleton
                animation="wave"
                variant="rounded"
                width="100%"
                height="100%"
              />
            </BodyItem>
          </div>
        )}
      />
    </ListItem>
  );
};
