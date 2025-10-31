import React, { useState } from 'react';
import { createFragmentContainer, graphql, useLazyLoadQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import { Link, useNavigate } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import { ChartTimeline, VectorLink, VectorPolygon } from 'mdi-material-ui';
import { ViewColumnOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import { useTheme } from '@mui/styles';
import { Box } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import StixCoreObjectMenuItemUnderEE from '../stix_core_objects/StixCoreObjectMenuItemUnderEE';
import StixCoreObjectSharingList from '../stix_core_objects/StixCoreObjectSharingList';
import StixCoreObjectBackgroundTasks from '../stix_core_objects/StixCoreObjectActiveBackgroundTasks';
import StixCoreObjectEnrollPlaybook from '../stix_core_objects/StixCoreObjectEnrollPlaybook';
import StixCoreObjectFileExportButton from '../stix_core_objects/StixCoreObjectFileExportButton';
import StixCoreObjectsSuggestions from '../stix_core_objects/StixCoreObjectsSuggestions';
import { DraftChip } from '../draft/DraftChip';
import { stixCoreObjectQuickSubscriptionContentQuery } from '../stix_core_objects/stixCoreObjectTriggersUtils';
import StixCoreObjectSubscribers from '../stix_core_objects/StixCoreObjectSubscribers';
import FormAuthorizedMembersDialog from '../form/FormAuthorizedMembersDialog';
import ExportButtons from '../../../../components/ExportButtons';
import Security from '../../../../utils/Security';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import StixCoreObjectSharing from '../stix_core_objects/StixCoreObjectSharing';
import useGranted, {
  AUTOMATION,
  KNOWLEDGE_KNENRICHMENT,
  KNOWLEDGE_KNGETEXPORT_KNASKEXPORT,
  KNOWLEDGE_KNUPDATE_KNDELETE,
  KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS,
  KNOWLEDGE_KNUPDATE_KNORGARESTRICT,
} from '../../../../utils/hooks/useGranted';
import StixCoreObjectQuickSubscription from '../stix_core_objects/StixCoreObjectQuickSubscription';
import StixCoreObjectFileExport from '../stix_core_objects/StixCoreObjectFileExport';
import { authorizedMembersToOptions, useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import StixCoreObjectEnrichment from '../stix_core_objects/StixCoreObjectEnrichment';
import { resolveLink } from '../../../../utils/Entity';
import PopoverMenu from '../../../../components/PopoverMenu';
import useAuth from '../../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../../settings/settings_messages/SettingsMessagesBanner';

export const containerHeaderObjectsQuery = graphql`
  query ContainerHeaderObjectsQuery($id: String!) {
    container(id: $id) {
      id
      x_opencti_graph_data
      confidence
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      creators {
        id
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      objects(all: true) {
        edges {
          types
          node {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on StixCoreObject {
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
            ... on StixDomainObject {
              is_inferred
              created
            }
            ... on AttackPattern {
              name
              x_mitre_id
            }
            ... on Campaign {
              name
              first_seen
              last_seen
            }
            ... on ObservedData {
              name
            }
            ... on CourseOfAction {
              name
            }
            ... on Note {
              attribute_abstract
              content
            }
            ... on Opinion {
              opinion
            }
            ... on Report {
              name
              published
            }
            ... on Grouping {
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
              valid_from
            }
            ... on Infrastructure {
              name
            }
            ... on IntrusionSet {
              name
              first_seen
              last_seen
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
              first_seen
              last_seen
            }
            ... on ThreatActor {
              name
              first_seen
              last_seen
            }
            ... on Tool {
              name
            }
            ... on Vulnerability {
              name
            }
            ... on Incident {
              name
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
            ... on Task {
              name
            }
            ... on Feedback {
              name
            }
            ... on CaseIncident {
              name
            }
            ... on StixCyberObservable {
              observable_value
            }
            ... on StixFile {
              observableName: name
            }
            ... on Label {
              value
              color
            }
            ... on MarkingDefinition {
              definition
              x_opencti_color
            }
            ... on KillChainPhase {
              kill_chain_name
              phase_name
            }
            ... on ExternalReference {
              url
              source_name
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreRelationship {
              relationship_type
              start_time
              stop_time
              confidence
              created
              is_inferred
              from {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
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
            ... on StixRefRelationship {
              relationship_type
              start_time
              stop_time
              confidence
              is_inferred
              from {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
              created_at
              objectMarking {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
            ... on StixSightingRelationship {
              relationship_type
              first_seen
              last_seen
              confidence
              created
              is_inferred
              from {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
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
          }
        }
      }
    }
  }
`;

const containerHeaderEditAuthorizedMembersMutation = graphql`
  mutation ContainerHeaderEditAuthorizedMembersMutation(
    $id: ID!
    $input: [MemberAccessInput!]
  ) {
    containerEdit(id: $id) {
      editAuthorizedMembers(input: $input) {
        authorized_members {
          id
          member_id
          name
          entity_type
          access_right
          groups_restriction {
            id
            name
          }
        }
      }
    }
  }
`;

const ContainerHeader = (props) => {
  const {
    container,
    EditComponent,
    DeleteComponent,
    link,
    modes,
    currentMode,
    knowledge,
    disableSharing,
    disableAuthorizedMembers,
    adjust,
    enableSuggestions,
    onApplied,
    enableQuickSubscription,
    investigationAddFromContainer,
    enableEnrollPlaybook,
    redirectToContent,
    enableEnricher,
  } = props;
  const theme = useTheme();
  const { t_i18n, fd } = useFormatter();
  const navigate = useNavigate();
  const [openEnrollPlaybook, setOpenEnrollPlaybook] = useState(false);
  const [openSharing, setOpenSharing] = useState(false);
  const [openAccessRestriction, setOpenAccessRestriction] = useState(false);
  const [openDelete, setOpenDelete] = useState(false);
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);

  const handleCloseEnrollPlaybook = () => {
    setOpenEnrollPlaybook(false);
  };

  const handleOpenDelete = () => setOpenDelete(true);

  const handleCloseDelete = () => setOpenDelete(false);

  const handleCloseSharing = () => {
    setOpenSharing(false);
  };

  const handleCloseAccessRestriction = () => {
    setOpenAccessRestriction(false);
  };

  const handleExportCompleted = (fileName) => {
    // navigate with fileName in query params to select the created file
    const fileParams = { currentFileId: fileName, contentSelected: false };
    const urlParams = new URLSearchParams(fileParams).toString();
    const entityLink = `${resolveLink(container.entity_type)}/${container.id}`;
    const targetTab = redirectToContent ? 'content' : 'files';
    navigate(`${entityLink}/${targetTab}?${urlParams}`);
  };

  const { bannerSettings: { bannerHeightNumber } } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  // containerDefault style
  let containerStyle = {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: theme.spacing(1),
  };
  const overrideContainerStyle = knowledge || currentMode === 'graph' || currentMode === 'correlation';
  if (overrideContainerStyle) {
    // container knowledge / graph style
    containerStyle = {
      position: 'absolute',
      display: 'flex',
      top: 166 + bannerHeightNumber + settingsMessagesBannerHeight,
      right: 24,
    };
  }
  const triggersPaginationOptions = {
    includeAuthorities: true,
    filters: {
      mode: 'and',
      filterGroups: [],
      filters: [
        {
          key: ['filters'],
          values: [container.id],
          operator: 'match',
          mode: 'or',
        },
        {
          key: ['instance_trigger'],
          values: ['true'],
          operator: 'eq',
          mode: 'or',
        },
      ],
    },
  };
  const isAuthorizedMembersEnabled = !disableAuthorizedMembers;
  const currentAccessRight = useGetCurrentUserAccessRight(container.currentUserAccessRight);
  const enableManageAuthorizedMembers = currentAccessRight.canManage && isAuthorizedMembersEnabled;

  // sharing buttons should be disabled for containers according to some autorized members conditions
  const isSharingDisabled = (!enableManageAuthorizedMembers && !currentAccessRight.canEdit)
    || (enableManageAuthorizedMembers && container.authorized_members && container.authorized_members.length > 0);

  const triggerData = useLazyLoadQuery(stixCoreObjectQuickSubscriptionContentQuery, { first: 20, ...triggersPaginationOptions });

  const displaySharing = !knowledge && disableSharing !== true;
  const displayAuthorizedMembers = !knowledge && !!enableManageAuthorizedMembers;
  const displayEnrollPlaybook = enableEnrollPlaybook;

  let initialNumberOfButtons = (!knowledge ? 1 : 0) + (enableQuickSubscription ? 1 : 0) + (enableEnricher ? 1 : 0);
  const displayEnrollPlaybookButton = displayEnrollPlaybook && initialNumberOfButtons < 3;
  if (displayEnrollPlaybookButton) initialNumberOfButtons += 1;
  const displaySharingButton = displaySharing && initialNumberOfButtons < 3;
  if (displaySharingButton) initialNumberOfButtons += 1;
  const displayAuthorizedMembersButton = displayAuthorizedMembers && initialNumberOfButtons < 3;

  const displayPopoverMenu = (displaySharing && !displaySharingButton)
    || (displayAuthorizedMembers && !displayAuthorizedMembersButton)
    || (displayEnrollPlaybook && !displayEnrollPlaybookButton) || (!knowledge && canDelete);

  return (
    <div style={containerStyle}>
      <React.Suspense fallback={<span />}>
        {!knowledge && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Tooltip
            title={
              container.name
              || container.attribute_abstract
              || container.content
              || container.opinion
              || `${fd(container.first_observed)} - ${fd(container.last_observed)}`
            }
          >
            <Typography variant="h1" sx={{ margin: 0, lineHeight: 'unset' }}>
              {truncate(
                container.name
                || container.attribute_abstract
                || container.content
                || container.opinion
                || `${fd(container.first_observed)} - ${fd(
                  container.last_observed,
                )}`,
                80,
              )}
            </Typography>
          </Tooltip>
          {container.draftVersion && (
            <DraftChip />
          )}
        </div>
        )}
        {knowledge && (
          <div>
            <ExportButtons
              domElementId="container"
              name={t_i18n('Report representation')}
              pixelRatio={currentMode === 'graph' ? 1 : 2}
              adjust={adjust}
              containerId={container.id}
              investigationAddFromContainer={investigationAddFromContainer}
            />
          </div>
        )}
        {modes && (
          <div id="container-view-buttons">
            <ToggleButtonGroup size="small" exclusive={true} style={{ marginLeft: theme.spacing(2) }}>
              {modes.includes('graph') && (
                <Tooltip title={t_i18n('Graph view')}>
                  <ToggleButton
                    value="graph"
                    component={Link}
                    to={`${link}/graph`}
                    selected={currentMode === 'graph'}
                  >
                    <VectorPolygon
                      fontSize="small"
                      color={currentMode === 'graph' ? 'primary' : 'inherit'}
                    />
                  </ToggleButton>
                </Tooltip>
              )}
              {modes.includes('timeline') && (
                <Tooltip title={t_i18n('TimeLine view')}>
                  <ToggleButton
                    value="timeline"
                    component={Link}
                    to={`${link}/timeline`}
                    selected={currentMode === 'timeline'}
                  >
                    <ChartTimeline
                      fontSize="small"
                      color={currentMode === 'timeline' ? 'primary' : 'inherit'}
                    />
                  </ToggleButton>
                </Tooltip>
              )}
              {modes.includes('correlation') && (
                <Tooltip title={t_i18n('Correlation view')}>
                  <ToggleButton
                    value="correlation"
                    component={Link}
                    to={`${link}/correlation`}
                    selected={currentMode === 'correlation'}
                  >
                    <VectorLink
                      fontSize="small"
                      color={
                        currentMode === 'correlation' ? 'primary' : 'inherit'
                      }
                    />
                  </ToggleButton>
                </Tooltip>
              )}
              {modes.includes('matrix') && (
                <Tooltip title={t_i18n('Tactics matrix view')}>
                  <ToggleButton
                    value="matrix"
                    component={Link}
                    to={`${link}/matrix`}
                    selected={currentMode === 'matrix'}
                  >
                    <ViewColumnOutlined
                      fontSize="small"
                      color={currentMode === 'matrix' ? 'primary' : 'inherit'}
                    />
                  </ToggleButton>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          </div>
        )}
        <div>
          <div style={{ display: 'flex' }}>
            {!knowledge && (
              <StixCoreObjectBackgroundTasks
                id={container.id}
                actionsFilter={['SHARE', 'UNSHARE', 'SHARE_MULTIPLE', 'UNSHARE_MULTIPLE']}
              />
            )}
            {enableQuickSubscription && (
              <StixCoreObjectSubscribers triggerData={triggerData} />
            )}
            {displaySharing && (
              <>
                <StixCoreObjectSharingList data={container} inContainer={true} />
                <StixCoreObjectSharing
                  elementId={container.id}
                  open={openSharing}
                  variant="header"
                  disabled={isSharingDisabled}
                  handleClose={displaySharingButton ? undefined : handleCloseSharing}
                  inContainer={true}
                />
              </>
            )}
            {displayAuthorizedMembers && (
              <FormAuthorizedMembersDialog
                id={container.id}
                owner={container.creators?.[0]}
                authorizedMembers={authorizedMembersToOptions(
                  container.authorized_members,
                )}
                mutation={containerHeaderEditAuthorizedMembersMutation}
                open={openAccessRestriction}
                handleClose={displayAuthorizedMembersButton ? undefined : handleCloseAccessRestriction}
                canDeactivate={true}
              />
            )}
            {!knowledge && (
              <Security needs={[KNOWLEDGE_KNGETEXPORT_KNASKEXPORT]}>
                <StixCoreObjectFileExport
                  scoId={container.id}
                  scoName={container.name}
                  scoEntityType={container.entity_type}
                  redirectToContentTab={!!redirectToContent}
                  OpenFormComponent={StixCoreObjectFileExportButton}
                  onExportCompleted={handleExportCompleted}
                />
              </Security>
            )}
            {enableSuggestions && (
              <StixCoreObjectsSuggestions
                containerId={container.id}
                currentMode={currentMode}
                onApplied={onApplied}
                containerHeaderObjectsQuery={containerHeaderObjectsQuery}
                container={container}
              />
            )}
            {enableQuickSubscription && (
              <StixCoreObjectQuickSubscription
                instanceId={container.id}
                instanceName={getMainRepresentative(container)}
                paginationOptions={triggersPaginationOptions}
                triggerData={triggerData}
              />
            )}
            {enableEnricher && (
              <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
                <StixCoreObjectEnrichment
                  stixCoreObjectId={container.id}
                />
              </Security>
            )}
            {displayEnrollPlaybook
              && <StixCoreObjectEnrollPlaybook
                stixCoreObjectId={container.id}
                open={openEnrollPlaybook}
                handleClose={displayEnrollPlaybookButton ? undefined : handleCloseEnrollPlaybook}
                 />
            }
            {displayPopoverMenu && (
              <>
                <PopoverMenu>
                  {({ closeMenu }) => (
                    <Box>
                      {displaySharing && !displaySharingButton && (
                      <StixCoreObjectMenuItemUnderEE
                        setOpen={setOpenSharing}
                        title={t_i18n('Share with an organization')}
                        isDisabled={isSharingDisabled}
                        handleCloseMenu={closeMenu}
                        needs={[KNOWLEDGE_KNUPDATE_KNORGARESTRICT]}
                      />
                      )}
                      {displayAuthorizedMembers && !displayAuthorizedMembersButton && (
                      <StixCoreObjectMenuItemUnderEE
                        setOpen={setOpenAccessRestriction}
                        title={t_i18n('Manage access restriction')}
                        handleCloseMenu={closeMenu}
                        isDisabled={!enableManageAuthorizedMembers}
                        needs={[KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]}
                      />
                      )}
                      {displayEnrollPlaybook && !displayEnrollPlaybookButton && (
                      <StixCoreObjectMenuItemUnderEE
                        title={t_i18n('Enroll in playbook')}
                        setOpen={setOpenEnrollPlaybook}
                        handleCloseMenu={closeMenu}
                        needs={[AUTOMATION]}
                        matchAll
                      />
                      )}
                      {canDelete && (
                      <MenuItem onClick={() => {
                        handleOpenDelete();
                        closeMenu();
                      }}
                      >
                        {t_i18n('Delete')}
                      </MenuItem>
                      )}
                    </Box>
                  )}
                </PopoverMenu>
                {DeleteComponent && (
                  <DeleteComponent isOpen={openDelete} onClose={handleCloseDelete} />
                )}
              </>
            )}
            {EditComponent}
          </div>
        </div>
      </React.Suspense>
    </div>
  );
};

export default createFragmentContainer(ContainerHeader, {
  container: graphql`
    fragment ContainerHeader_container on Container {
      ...StixCoreObjectSharingListFragment
      id
      draftVersion {
        draft_id
        draft_operation
      }
      entity_type
      standard_id
      confidence
      created
      creators {
        id
        name
        entity_type
      }
      filesFromTemplate(first: 500) {
        edges {
          node {
            id
            name
            objectMarking {
              id
              representative {
                main
              }
            }
          }
        }
      }
      fintelTemplates {
        id
        name
      }
      currentUserAccessRight
      authorized_members {
        id
        member_id
        name
        entity_type
        access_right
        groups_restriction {
          id
          name
        }
      }
      ... on Report {
        name
      }
      ... on Grouping {
        name
      }
      ... on Case {
        name
      }
      ... on Feedback {
        name
      }
      ... on Task {
        name
      }
      ... on CaseIncident {
        name
      }
      ... on CaseRfi {
        name
      }
      ... on CaseRft {
        name
      }
      ... on Note {
        attribute_abstract
        content
      }
      ... on Opinion {
        opinion
      }
      ... on ObservedData {
        name
        first_observed
        last_observed
      }
      createdBy {
        id
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
    }
  `,
});
