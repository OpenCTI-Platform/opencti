import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { CircleOutlined } from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { InvestigationAddStixCoreObjectsLine_node$data } from '@components/workspaces/investigations/__generated__/InvestigationAddStixCoreObjectsLine_node.graphql';
import { ListItemButton } from '@mui/material';
import { Checkbox } from '@filigran/design-system';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { DataColumns } from '../../../../components/list_lines';
import ItemEntityType from '../../../../components/ItemEntityType';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import { EMPTY_VALUE } from '../../../../utils/String';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface InvestigationAddStixCoreObjectsLineComponentProps {
  dataColumns: DataColumns;
  node: InvestigationAddStixCoreObjectsLine_node$data;
  onLabelClick: HandleAddFilter;
  onToggleEntity: (
    entity: InvestigationAddStixCoreObjectsLine_node$data,
    event: React.SyntheticEvent,
  ) => void;
  addedElements: {
    [key: string]: InvestigationAddStixCoreObjectsLine_node$data;
  };
}

const InvestigationAddStixCoreObjectsLineComponent = ({
  dataColumns,
  node,
  onLabelClick,
  onToggleEntity,
  addedElements,
}: InvestigationAddStixCoreObjectsLineComponentProps) => {
  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      onClick={(event) => onToggleEntity(node, event)}
    >
      <ListItemIcon style={{ paddingLeft: 10 }}>
        <Checkbox checked={node.id in (addedElements || {})} />
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
              style={{ width: dataColumns.value.width }}
            >
              {getMainRepresentative(node)}
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
                markingDefinitions={(node.objectMarking ?? [])}
                limit={1}
              />
            </BodyItem>
          </div>
        )}
      />
    </ListItemButton>
  );
};

export const InvestigationAddStixCoreObjectsLine = createFragmentContainer(
  InvestigationAddStixCoreObjectsLineComponent,
  {
    node: graphql`
      fragment InvestigationAddStixCoreObjectsLine_node on StixCoreObject {
        id
        standard_id
        parent_types
        entity_type
        created_at
        numberOfConnectedElement
        ... on StixDomainObject {
          created
        }
        ... on AttackPattern {
          name
          description
          x_mitre_id
        }
        ... on Campaign {
          name
          description
          first_seen
          last_seen
        }
        ... on Channel {
          name
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
        }
        ... on Report {
          name
          description
          published
        }
        ... on Grouping {
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
        ... on SecurityPlatform{
          name
          description
          security_platform_type
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
          valid_from
        }
        ... on Infrastructure {
          name
          description
        }
        ... on IntrusionSet {
          name
          description
          first_seen
          last_seen
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
          first_seen
          last_seen
        }
        ... on MalwareAnalysis {
          result_name
        }
        ... on ThreatActor {
          name
          description
          first_seen
          last_seen
        }
        ... on Tool {
          name
          description
        }
        ... on Task {
          name
        }
        ... on Narrative {
          name
        }
        ... on Vulnerability {
          name
          description
        }
        ... on Event {
          name
        }
        ... on Incident {
          name
          description
          first_seen
          last_seen
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
          x_opencti_description
          ... on StixFile {
            hashes {
              algorithm
              hash
            }
          }
        }
        ... on SecurityCoverage {
          name
        }
        ... on SecurityCoverageResult {
          name
        }
        ... on StixFile {
          observableName: name
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

interface InvestigationAddStixCoreObjecstLineDummyProps {
  dataColumns: DataColumns;
}

export const InvestigationAddStixCoreObjecstLineDummy = (
  { dataColumns }: InvestigationAddStixCoreObjecstLineDummyProps,
) => {
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      style={{ minWidth: 40 }}
    >
      <ListItemIcon
        sx={{ color: (theme) => theme.palette.grey?.[700] }}
        style={{ minWidth: 40 }}
      >
        <CircleOutlined />
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
              style={{ width: dataColumns.value.width }}
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
    </ListItem>
  );
};
