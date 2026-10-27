import React from 'react';
import { Link } from 'react-router';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import Tooltip from '@mui/material/Tooltip';
import { AutoFix } from 'mdi-material-ui';
import { Chip } from '@filigran/design-system';
import IconButton from '@common/button/IconButton';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ContainerStixCoreObjectPopover from './ContainerStixCoreObjectPopover';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemMarkings from '../../../../components/ItemMarkings';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import ItemEntityType from '../../../../components/ItemEntityType';
import { DraftChip } from '../draft/DraftChip';
import { EMPTY_VALUE } from '../../../../utils/String';
import { Checkbox } from '@filigran/design-system';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';
import { useComputeLink } from '../../../../utils/hooks/useAppData';

const itemSx = {
  paddingLeft: '10px',
  height: 50,
};

const BodyItem = styled('div')(bodyItemStyle);

const ContainerStixDomainObjectLineComponent = (props) => {
  const {
    node,
    types,
    dataColumns,
    containerId,
    paginationOptions,
    onToggleEntity,
    selectedElements,
    deSelectedElements,
    selectAll,
    onToggleShiftEntity,
    enableReferences,
    index,
  } = props;
  const { t_i18n, fd, n } = useFormatter();
  const computeLink = useComputeLink();
  const refTypes = types ?? ['manual'];
  const isThroughInference = refTypes.includes('inferred');
  const isOnlyThroughInference = isThroughInference && !refTypes.includes('manual');
  const link = computeLink(node);
  const linkAnalyses = `${link}/analyses`;
  return (
    <ListItem
      divider={true}
      disablePadding
      secondaryAction={isOnlyThroughInference ? (
        <Tooltip title={t_i18n('Inferred knowledge')}>
          <AutoFix fontSize="small" style={{ marginLeft: -30 }} />
        </Tooltip>
      ) : (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ContainerStixCoreObjectPopover
            containerId={containerId}
            toId={node.id}
            toStandardId={node.standard_id}
            relationshipType="object"
            paginationKey="Pagination_objects"
            paginationOptions={paginationOptions}
            enableReferences={enableReferences}
          />
        </Security>
      )}
    >
      <ListItemButton
        component={Link}
        sx={itemSx}
        to={link}
      >
        <ListItemIcon
          sx={{ color: 'primary.main' }}
          style={{ minWidth: 40 }}
          onClick={(event) => !isOnlyThroughInference
            && (event.shiftKey
              ? onToggleShiftEntity(index, node, event)
              : onToggleEntity(node, event))
          }
        >
          <Checkbox
            disabled={isOnlyThroughInference}
            checked={
              (selectAll
                && !isOnlyThroughInference
                && !(node.id in (deSelectedElements || {})))
              || node.id in (selectedElements || {})
            }
          />
        </ListItemIcon>
        <ListItemIcon sx={{ color: 'primary.main' }}>
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
                {node.x_mitre_id
                  ? `[${node.x_mitre_id}] ${node.name}`
                  : getMainRepresentative(node)}
                {node.draftVersion && (<DraftChip />)}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.objectLabel.width }}
              >
                <StixCoreObjectLabels
                  variant="inList"
                  labels={node.objectLabel}
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.createdBy.width }}
              >
                {node.createdBy?.name ?? EMPTY_VALUE}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.created_at.width }}
              >
                {fd(node.created_at)}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.analyses.width }}
              >
                {[
                  'Note',
                  'Opinion',
                  'Course-Of-Action',
                  'Data-Component',
                  'Data-Source',
                ].includes(node.entity_type) ? (
                      <Chip
                        severity="neutral"
                        label={n(node.containersNumber.total)}
                      />
                    ) : (
                      <Link to={linkAnalyses}>
                        <Chip severity="neutral" label={n(node.containersNumber.total)} />
                      </Link>
                    )}
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
    </ListItem>
  );
};

export const ContainerStixDomainObjectLine = createFragmentContainer(
  ContainerStixDomainObjectLineComponent,
  {
    node: graphql`
      fragment ContainerStixDomainObjectLine_node on StixDomainObject {
        id
        draftVersion {
          draft_id
          draft_operation
        }
        standard_id
        entity_type
        parent_types
        created_at
        ... on AttackPattern {
          name
          x_mitre_id
        }
        ... on Campaign {
          name
        }
        ... on CourseOfAction {
          name
        }
        ... on ObservedData {
          name
        }
        ... on Report {
          name
        }
        ... on Grouping {
          name
        }
        ... on Note {
          attribute_abstract
          content
        }
        ... on Opinion {
          opinion
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
        ... on SecurityCoverage {
          name
        }
        ... on SecurityCoverageResult {
          name
          resultOf {
            id
          }
        }
        ... on Task {
          name
        }
        objectLabel {
          id
          value
          color
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
        containersNumber {
          total
        }
      }
    `,
  },
);

export const ContainerStixDomainObjectLineDummy = (props) => {
  const { t_i18n } = useFormatter();
  const { dataColumns } = props;
  return (
    <ListItem
      sx={itemSx}
      divider={true}
      secondaryAction={(
        <IconButton
          disabled={true}
          aria-label={t_i18n('Open menu')}
          keepMui
        >
          <MoreVert />
        </IconButton>
      )}
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
              style={{ width: dataColumns.created_at.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.analyses.width }}
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
