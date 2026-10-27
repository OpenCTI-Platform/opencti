import React, { FunctionComponent } from 'react';
import { Link } from 'react-router';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import { ListItemButton } from '@mui/material';
import { typesWithFintelTemplates } from 'src/utils/hooks/useAttributes';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import { resolveLink } from '../../../../utils/Entity';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemStatus from '../../../../components/ItemStatus';
import ItemMarkings from '../../../../components/ItemMarkings';
import { DataColumns } from '../../../../components/list_lines';
import { StixCoreObjectOrStixCoreRelationshipContainerLine_node$data } from './__generated__/StixCoreObjectOrStixCoreRelationshipContainerLine_node.graphql';
import ItemEntityType from '../../../../components/ItemEntityType';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import { EMPTY_VALUE } from '../../../../utils/String';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const itemSx = {
  paddingLeft: '10px',
  height: 50,
};

const goIconSx = {
  position: 'absolute',
  right: -10,
} as const;

const BodyItem = styled('div')(bodyItemStyle);

interface StixCoreObjectOrStixCoreRelationshipContainerLineComponentProps {
  node: StixCoreObjectOrStixCoreRelationshipContainerLine_node$data;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
  redirectionMode: string;
}

export const StixCoreObjectOrStixCoreRelationshipContainerLineComponent: FunctionComponent<
  StixCoreObjectOrStixCoreRelationshipContainerLineComponentProps
> = ({ node, dataColumns, onLabelClick, redirectionMode }) => {
  const { fd } = useFormatter();

  const isContainer = typesWithFintelTemplates.includes(node.entity_type);
  let redirectionLink = `${resolveLink(node.entity_type)}/${node.id}`;
  if (redirectionMode !== 'overview' && isContainer) redirectionLink += `/${redirectionMode}`;

  return (
    <ListItemButton
      sx={itemSx}
      divider={true}
      component={Link}
      to={redirectionLink}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <ItemIcon type={node.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <>
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
                onClick={onLabelClick.bind(this)}
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.created.width }}
            >
              {fd(node.first_observed || node.published || node.created)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.x_opencti_workflow_id.width }}
            >
              <ItemStatus
                status={node.status}
                disabled={!node.workflowEnabled}
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.objectMarking.width }}
            >
              <ItemMarkings
                markingDefinitions={node.objectMarking ?? []}
                limit={1}
              />
            </BodyItem>
          </>
        )}
      />
      <ListItemIcon sx={goIconSx}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

const StixCoreObjectOrStixCoreRelationshipContainerLineFragment = createFragmentContainer(
  StixCoreObjectOrStixCoreRelationshipContainerLineComponent,
  {
    node: graphql`
        fragment StixCoreObjectOrStixCoreRelationshipContainerLine_node on Container {
          id
          workflowEnabled
          entity_type
          status {
            id
            order
            template {
              name
              color
            }
          }
          creators {
            id
            name
          }
          ... on Note {
            attribute_abstract
            content
            created
          }
          ... on Opinion {
            opinion
            created
          }
          ... on ObservedData {
            name
            first_observed
            last_observed
          }
          ... on Report {
            name
            published
          }
          ... on Grouping {
            name
            created
          }
          ... on Case {
            name
            created
          }
          ... on Task {
            name
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
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
          ... on ObservedData {
            name
            objects(first: 1) {
              edges {
                node {
                  ... on StixCoreObject {
                    id
                    entity_type
                    parent_types
                    created_at
                    createdBy {
                      ... on Identity {
                        id
                        name
                        entity_type
                      }
                    }
                    objectMarking {
                      id
                      definition_type
                      definition
                      x_opencti_order
                      x_opencti_color
                    }
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
                  ... on Note {
                    attribute_abstract
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
                  ... on Vulnerability {
                    name
                    description
                  }
                  ... on Incident {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Event {
                    name
                    description
                    start_time
                    stop_time
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
                    x_opencti_description
                  }
                }
              }
            }
          }
        }
      `,
  },
);

export const StixCoreObjectOrStixCoreRelationshipContainerLine = StixCoreObjectOrStixCoreRelationshipContainerLineFragment;

interface StixCoreObjectOrStixCoreRelationshipContainerLineDummyProps {
  dataColumns: DataColumns;
}

export const StixCoreObjectOrStixCoreRelationshipContainerLineDummy: FunctionComponent<
  StixCoreObjectOrStixCoreRelationshipContainerLineDummyProps
> = ({ dataColumns }) => {
  return (
    <ListItem sx={itemSx} divider={true}>
      <ListItemIcon sx={{ color: 'grey.700' }}>
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
              style={{ width: dataColumns.created.width }}
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
      <ListItemIcon sx={goIconSx}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};
