import IconButton from '@common/button/IconButton';
import {
  AutoFixHighOutlined,
  BrushOutlined,
  CheckCircleOutlined,
  ClearOutlined,
  ContentCopyOutlined,
  DeleteOutlined,
  DeleteSweepOutlined,
  LinkOffOutlined,
  LockOpenOutlined,
  MergeOutlined,
  MoveToInboxOutlined,
  PrecisionManufacturingOutlined,
  RestoreOutlined,
  TransformOutlined,
  UnpublishedOutlined,
} from '@mui/icons-material';
import Toolbar from '@mui/material/Toolbar';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { BankMinus, BankPlus, CloudRefreshOutline } from 'mdi-material-ui';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import React, { useContext, useState } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import { useFormatter } from '../../../components/i18n';
import { commitMutation, fetchQuery, MESSAGING$ } from '../../../relay/environment';
import Security from '../../../utils/Security';
import { getEntityTypeThreeFirstLevelsFilterValues, removeIdAndIncorrectKeysFromFilterGroupObject, serializeFilterGroupForBackend } from '../../../utils/filters/filtersUtils';
import { UserContext } from '../../../utils/hooks/useAuth';
import {
  AUTOMATION,
  BYPASS,
  EXPLORE_EXUPDATE_EXDELETE,
  EXPLORE_EXUPDATE_PUBLISH,
  INVESTIGATION_INUPDATE_INDELETE,
  KNOWLEDGE_KNUPDATE,
  KNOWLEDGE_KNUPDATE_KNDELETE,
  KNOWLEDGE_KNUPDATE_KNMERGE,
  KNOWLEDGE_KNUPDATE_KNORGARESTRICT,
  SETTINGS_SETACCESSES,
} from '../../../utils/hooks/useGranted';

import EETooltip from '../common/entreprise_edition/EETooltip';
import UserEmailSend from '../settings/users/UserEmailSend';
import PromoteDrawer from './drawers/PromoteDrawer';
import { isBulkActionAllowed, isBulkActionDisabled } from './dataTableToolBarActionRules';
import { buildUpdateActions } from './dataTableToolBarUpdateSteps';
import { toUserOptions } from './dataTableToolBarStepOptions';
import EnrichmentDrawer from './drawers/EnrichmentDrawer';
import MergeDrawer from './drawers/MergeDrawer';
import RuleRescanDrawer from './drawers/RuleRescanDrawer';
import BulkUpdateDrawer from './drawers/BulkUpdateDrawer';
import AddInContainerDialog from './dialogs/AddInContainerDialog';
import BackgroundTaskDialog from './dialogs/BackgroundTaskDialog';
import { buildTaskActions } from './dataTableToolBarTask';
import OrganizationSharingDialog from './dialogs/OrganizationSharingDialog';
import useCustomFieldDefinitions from '../common/custom_fields/useCustomFieldDefinitions';
import { getCustomFieldDefinitionsOfTypes, getTaskTargetedTypes } from '../../../utils/customFields';

import EnrollPlaybookDrawer from '@components/data/drawers/EnrollPlaybookDrawer';

// Only the toolbar itself is styled here, the dialogs and drawers own their styles
const useStyles = makeStyles(() => ({
  title: {
    flex: '1 1 100%',
    fontSize: '12px',
    marginBottom: '1px',
  },
  editButtons: {
    display: 'flex',
    alignItems: 'center',
    gap: 4,
    '& > span': {
      display: 'inline-flex',
      alignItems: 'center',
    },
  },
}));

const toolBarListTaskAddMutation = graphql`
  mutation DataTableToolBarListTaskAddMutation($input: ListTaskAddInput!) {
    listTaskAdd(input: $input) {
      id
      type
    }
  }
`;

const toolBarQueryTaskAddMutation = graphql`
  mutation DataTableToolBarQueryTaskAddMutation($input: QueryTaskAddInput!) {
    queryTaskAdd(input: $input) {
      id
      type
    }
  }
`;

const toolBarConnectorsQuery = graphql`
  query DataTableToolBarConnectorsQuery($type: String!) {
    enrichmentConnectors(type: $type) {
      id
      name
    }
  }
`;

export const maxNumberOfObservablesToCopy = 1000;

export const toolBarUsersLinesSearchQuery = graphql`
    query  DataTableToolBarUsersLinesSearchQuery(
        $first: Int, $search: String,
        $orderBy: UsersOrdering
        $orderMode: OrderingMode
    ) {
        users(first: $first, search: $search, orderBy: $orderBy, orderMode: $orderMode) {
            edges {
                node {
                    id
                    entity_type
                    name
                    user_email
                }
            }
        }
    }
`;

const fetchUserOptions = (search) => fetchQuery(toolBarUsersLinesSearchQuery, { search, first: 100 })
  .toPromise()
  .then(toUserOptions);

const DataTableToolBar = ({
  numberOfSelectedElements,
  handleClearSelectedElements,
  selectedElements,
  deSelectedElements,
  selectAll,
  filters,
  search,
  container,
  type,
  types,
  handleCopy,
  noAuthor,
  noMarking,
  noWarning,
  deleteDisable,
  mergeDisable,
  trashOperationsEnabled,
  disableBulkEnroll,
  removeAuthMembersEnabled,
  removeFromDraftEnabled,
  markAsReadEnabled,
  warning,
  warningMessage,
  taskScope,
}) => {
  const classes = useStyles();
  const { t_i18n: t } = useFormatter();
  const { schema, settings, me, platformModuleHelpers } = useContext(UserContext);
  // The update entities drawer offers the custom fields: their definitions are loaded once elements are selected
  const customFieldDefinitions = useCustomFieldDefinitions(numberOfSelectedElements > 0);

  const [displayTask, setDisplayTask] = useState(false);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [displayEnrichment, setDisplayEnrichment] = useState(false);
  const [displayRescan, setDisplayRescan] = useState(false);
  const [displayMerge, setDisplayMerge] = useState(false);
  const [displayAddInContainer, setDisplayAddInContainer] = useState(false);
  const [displayShare, setDisplayShare] = useState(false);
  const [displayUnshare, setDisplayUnshare] = useState(false);
  const [displayPromote, setDisplayPromote] = useState(false);
  const [displayEnrollPlaybook, setDisplayEnrollPlaybook] = useState(false);
  const [displaySendEmail, setDisplaySendEmail] = useState(false);
  const [actions, setActions] = useState([]);
  const [description, setDescription] = useState('');
  const [processing, setProcessing] = useState(false);
  const [addInContainerStep, setAddInContainerStep] = useState({});
  const [keptEntityId, setKeptEntityId] = useState(null);
  const [mergingElement, setMergingElement] = useState(null);
  const [enrichConnectors, setEnrichConnectors] = useState([]);
  const [organizationInput, setOrganizationInput] = useState('');
  const [shareOrganizations, setShareOrganizations] = useState([]);
  const [promoteToContainer, setPromoteToContainer] = useState();

  // Every action ends in the background task dialog, which shows the task before it is launched
  const openTask = (nextActions, nextDescription) => {
    setActions(nextActions);
    if (nextDescription !== undefined) setDescription(nextDescription);
    setDisplayTask(true);
  };

  const handleCloseTask = () => {
    setDisplayTask(false);
    setActions([]);
    setKeptEntityId(null);
    setMergingElement(null);
    setProcessing(false);
    setDescription('');
  };

  const handleOpenUpdate = () => setDisplayUpdate(true);
  // Kept from the steps shared with the update drawer: closing it also clears the container step
  const handleCloseUpdate = () => {
    setDisplayUpdate(false);
    setAddInContainerStep({});
  };
  const handleOpenRescan = () => setDisplayRescan(true);
  const handleOpenMerge = () => setDisplayMerge(true);
  const handleOpenAddInContainer = () => setDisplayAddInContainer(true);
  const handleOpenShare = () => setDisplayShare(true);
  const handleOpenUnshare = () => setDisplayUnshare(true);
  const handleOpenPromote = () => setDisplayPromote(true);
  const handleOpenEnrollPlaybook = () => setDisplayEnrollPlaybook(true);
  const handleCloseSendEmail = () => setDisplaySendEmail(false);

  const handleOpenEnrichment = (stixCyberObservableSubTypes, stixDomainObjectSubTypes) => {
    let enrichType;
    if (selectAll) {
      const entityTypeFilterValues = getEntityTypeThreeFirstLevelsFilterValues(filters, stixCyberObservableSubTypes, stixDomainObjectSubTypes);
      enrichType = type ?? R.head(entityTypeFilterValues);
    } else {
      const selectedElementsList = Object.values(selectedElements || {});
      enrichType = R.head(R.uniq(selectedElementsList
        .map((o) => o.entity_type)
        .filter((entity_type) => entity_type !== undefined)));
    }
    fetchQuery(toolBarConnectorsQuery, { type: enrichType })
      .toPromise()
      .then((data) => {
        setDisplayEnrichment(true);
        setEnrichConnectors(data.enrichmentConnectors ?? []);
      });
  };

  const handleLaunchEnrollPlaybook = (playbookId, playbookName) => {
    setDisplayEnrollPlaybook(false);
    openTask(
      [{ type: 'ENROLL_PLAYBOOK', context: { values: [{ id: playbookId, name: playbookName }] } }],
      `ENROLL IN PLAYBOOK ${playbookName}`,
    );
  };

  const handleLaunchAddInContainer = () => {
    const step = { ...addInContainerStep, type: 'ADD', fieldType: 'ATTRIBUTE', field: 'container-object' };
    setDisplayAddInContainer(false);
    handleCloseUpdate();
    openTask(buildUpdateActions([step]));
  };

  const handleLaunchUpdateSteps = (steps) => {
    handleCloseUpdate();
    openTask(buildUpdateActions(steps));
  };

  const handleLaunchRead = (read) => openTask([{
    type: 'REPLACE',
    context: { field: 'is_read', type: 'ATTRIBUTE', values: [read ? 'true' : 'false'] },
  }]);
  const handleLaunchDelete = () => openTask([{ type: 'DELETE', context: null }]);
  const handleLaunchRemoveAuthMembers = () => openTask([{ type: 'REMOVE_AUTH_MEMBERS', context: null }]);
  const handleLaunchRemoveFromDraft = () => openTask([{ type: 'REMOVE_FROM_DRAFT', context: null }]);
  const handleLaunchRemove = () => openTask([{ type: 'REMOVE', context: { field: 'container-object', values: [container] } }]);
  const handleLaunchCompleteDelete = () => openTask([{ type: 'COMPLETE_DELETE', context: null }]);
  const handleLaunchRestore = () => openTask([{ type: 'RESTORE', context: null }]);

  const handleLaunchRescan = () => {
    setDisplayRescan(false);
    openTask([{ type: 'RULE_ELEMENT_RESCAN' }]);
  };

  const handleLaunchPromote = () => {
    setDisplayPromote(false);
    openTask([{ type: 'PROMOTE' }]);
  };

  const handleLaunchEnrichment = (connectorIds) => {
    setDisplayEnrichment(false);
    openTask([{ type: 'ENRICHMENT', context: { values: connectorIds } }]);
  };

  const handleLaunchMerge = (keptElement, mergedElements) => {
    setDisplayMerge(false);
    setMergingElement(keptElement);
    openTask([{ type: 'MERGE', context: { values: mergedElements } }]);
  };

  const handleLaunchSharing = (mode, organizations) => {
    if (mode === 'share') setDisplayShare(false);
    else setDisplayUnshare(false);
    const orgaNames = organizations.map((o) => o.label).join('|');
    openTask(
      [{ type: mode === 'share' ? 'SHARE_MULTIPLE' : 'UNSHARE_MULTIPLE', context: { values: organizations } }],
      `${mode === 'share' ? 'SHARE' : 'UNSHARE'} with organizations ${orgaNames}`,
    );
  };

  const handleSubmitEmailTemplate = (emailTemplate) => {
    handleCloseSendEmail();
    openTask([{ type: 'SEND_EMAIL', context: { values: [emailTemplate.id] } }]);
  };

  const submitTask = (availableFilterKeys, isInDraft) => {
    setProcessing(true);
    const scope = taskScope ?? 'KNOWLEDGE';
    if (numberOfSelectedElements === 0) return;
    const finalActions = buildTaskActions(actions, { taskScope, promoteToContainer, containerId: container?.id });
    const onCompleted = () => {
      handleClearSelectedElements();
      const monitoringLink = !isInDraft ? <Link to="/dashboard/data/processing/tasks">{t('the dedicated page')}</Link> : t('the draft processes tab');
      MESSAGING$.notifySuccess(
        <span>
          {t('The background task has been executed. You can monitor it on')}{' '}
          {monitoringLink}
          .
        </span>,
      );
      setProcessing(false);
      handleCloseTask();
    };
    if (selectAll) {
      commitMutation({
        mutation: toolBarQueryTaskAddMutation,
        variables: {
          input: {
            description,
            filters: serializeFilterGroupForBackend(removeIdAndIncorrectKeysFromFilterGroupObject(filters, availableFilterKeys)),
            search,
            actions: finalActions,
            excluded_ids: Object.keys(deSelectedElements || {}),
            scope,
          },
        },
        onCompleted,
      });
    } else {
      commitMutation({
        mutation: toolBarListTaskAddMutation,
        variables: {
          input: {
            description,
            ids: mergingElement ? [mergingElement.id] : Object.keys(selectedElements),
            actions: finalActions,
            scope,
          },
        },
        onCompleted,
      });
    }
  };

  const isUserDatatable = taskScope === 'USER';
  let deleteCapability = KNOWLEDGE_KNUPDATE_KNDELETE;
  if (taskScope === 'DASHBOARD') deleteCapability = EXPLORE_EXUPDATE_EXDELETE;
  if (taskScope === 'PUBLIC_DASHBOARD') deleteCapability = EXPLORE_EXUPDATE_PUBLISH;
  if (taskScope === 'INVESTIGATION') deleteCapability = INVESTIGATION_INUPDATE_INDELETE;

  const isAdmin = me.capabilities.map((o) => o.name).filter((o) => [SETTINGS_SETACCESSES, BYPASS].includes(o)).length > 0;
  const isInDraft = me.draftContext;
  const isRuleEngineEnabled = platformModuleHelpers.isRuleEngineEnable();

  const stixCyberObservableSubTypes = schema.scos.map((sco) => sco.id);
  const stixDomainObjectSubTypes = schema.sdos.map((sdo) => sdo.id);
  const entityTypeFilterValues = getEntityTypeThreeFirstLevelsFilterValues(filters, stixCyberObservableSubTypes, stixDomainObjectSubTypes);
  const selectedElementsList = Object.values(selectedElements || {});
  const selectedTypes = R.uniq([...selectedElementsList.map((o) => o.entity_type), ...entityTypeFilterValues]
    .filter((entity_type) => entity_type !== undefined));
  // Some filter types are high level, we do not want to check them as "Different"
  // We might need to add some other types here before refactoring the toolbar
  const elementsTypes = selectedElementsList.length > 0
    ? R.uniq(selectedElementsList.map((e) => e.entity_type))
    : selectedTypes;
  const typesAreDifferent = elementsTypes.filter((type) => !['Stix-Core-Object', 'Stix-Domain-Object', 'stix-core-relationship', 'Stix-Cyber-Observable'].includes(type)).length > 1;
  const preventMerge = selectedTypes.at(0) === 'Vocabulary'
    && Object.values(selectedElements).some(({ builtIn }) => Boolean(builtIn));
  // region update
  const typesAreNotUpdatable = isBulkActionDisabled('update', selectedTypes, entityTypeFilterValues);
  // endregion
  // region rules
  const typesAreNotScannable = isBulkActionDisabled('scan', selectedTypes, entityTypeFilterValues);
  // endregion
  // region enrich
  const isManualEnrichSelect = !selectAll && (selectedTypes.filter((st) => !['Stix-Cyber-Observable', 'Stix-Domain-Object'].includes(st))).length === 1;
  const isAllEnrichSelect = selectAll
    && entityTypeFilterValues.length === 1
    && entityTypeFilterValues[0] !== 'Stix-Cyber-Observable'
    && entityTypeFilterValues[0] !== 'Stix-Domain-Object';
  const enrichDisable = isBulkActionDisabled('enrich', selectedTypes, entityTypeFilterValues)
    || (!isManualEnrichSelect && !isAllEnrichSelect);
  // endregion
  // region orgaSharing
  const isShareableType = isBulkActionAllowed('share', selectedTypes[0]);
  // endregion
  // region merge
  const typesAreNotMergable = !isBulkActionAllowed('merge', selectedTypes[0]);
  const enableMerge = !typesAreNotMergable && !mergeDisable;
  // The entity type filter is checked against the scan rule, not the add one (behavior kept as is)
  const typesAreNotAddableInContainer = !isBulkActionAllowed('addInContainer', selectedTypes[0])
    || (entityTypeFilterValues.length === 1
      && !isBulkActionAllowed('scan', entityTypeFilterValues[0]));
  const titleCopy = numberOfSelectedElements > maxNumberOfObservablesToCopy
    ? `${t('Copy disabled: too many selected elements (maximum number of elements for a copy: ') + maxNumberOfObservablesToCopy})`
    : t('Copy to clipboard');
  // endregion
  // region EE
  const isEnterpriseEdition = settings.platform_enterprise_edition.license_validated;
  // endregion
  // region promote filters
  const stixCyberObservableTypes = schema.scos.map((sco) => sco.id).concat('Stix-Cyber-Observable');
  const promotionTypes = stixCyberObservableTypes.concat(['Indicator']);

  const isOnlyStixCyberObservablesTypes = entityTypeFilterValues.length > 0
    && entityTypeFilterValues.every((id) => stixCyberObservableTypes.includes(id));

  const promotionTypesFiltered = entityTypeFilterValues.length > 0
    && entityTypeFilterValues.every((id) => promotionTypes.includes(id));

  const cleanedSelectedTypes = selectedTypes.filter((type) => type !== 'Stix-Domain-Object' && type !== 'Stix-Core-Object');

  const isManualPromoteSelect = !selectAll
    && cleanedSelectedTypes.length > 0
    && cleanedSelectedTypes.every((type) => promotionTypes.includes(type));

  const promoteEnabled = isManualPromoteSelect || promotionTypesFiltered;

  const entityTypes = selectedTypes.length > 0 ? selectedTypes : [type ?? 'Stix-Core-Object'];
  // Only the custom fields carried by every targeted type are offered
  const customFieldDefinitionsOfTypes = getCustomFieldDefinitionsOfTypes(
    customFieldDefinitions,
    getTaskTargetedTypes(selectAll, selectedElementsList, entityTypeFilterValues, types),
    (type) => schema.scrs.some((scr) => scr.label === type),
  );
  const filterKeysMap = new Map();
  entityTypes.forEach((entityType) => {
    const currentMap = schema.filterKeysSchema.get(entityType);
    currentMap?.forEach((value, key) => filterKeysMap.set(key, value));
  });
  const availableFilterKeys = Array.from(filterKeysMap.keys()).concat(['entity_type']);
  const isContainer = !!container?.id;
  // endregion
  return (
    <>
      <Toolbar style={{ minHeight: 40, display: 'flex', justifyContent: 'space-between', height: '100%', paddingRight: 12, paddingLeft: 8, alignItems: 'center' }} data-testid="opencti-toolbar">
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <Typography
            className={classes.title}
            color="inherit"
            variant="subtitle1"
          >
            <strong>{numberOfSelectedElements}</strong> {t('selected')}{' '}
          </Typography>
          <IconButton
            aria-label="clear"
            disabled={
              numberOfSelectedElements === 0 || processing
            }
            onClick={handleClearSelectedElements}
          >
            <ClearOutlined />
          </IconButton>
        </div>
        <div className={classes.editButtons}>
          {markAsReadEnabled && (
            <>
              <Tooltip title={t('Mark as read')}>
                <span>
                  <IconButton
                    aria-label={t('Mark as read')}
                    disabled={numberOfSelectedElements === 0 || processing}
                    onClick={() => handleLaunchRead(true)}
                    size="small"
                  >
                    <CheckCircleOutlined fontSize="small" color="success" />
                  </IconButton>
                </span>
              </Tooltip>
              <Tooltip title={t('Mark as unread')}>
                <span>
                  <IconButton
                    aria-label={t('Mark as unread')}
                    disabled={numberOfSelectedElements === 0 || processing}
                    onClick={() => handleLaunchRead(false)}
                    size="small"
                  >
                    <UnpublishedOutlined fontSize="small" color="error" />
                  </IconButton>
                </span>
              </Tooltip>
            </>
          )}
          {removeAuthMembersEnabled && (
            <Security needs={[BYPASS]}>
              <Tooltip title={t('Remove access restriction')}>
                <IconButton
                  color="primary"
                  aria-label="input"
                  data-testid="remove-auth-members-button"
                  onClick={handleLaunchRemoveAuthMembers}
                  size="small"
                  disabled={
                    numberOfSelectedElements === 0
                    || processing
                  }
                >
                  <LockOpenOutlined />
                </IconButton>
              </Tooltip>
            </Security>
          )}
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            {!typesAreNotUpdatable && !removeAuthMembersEnabled && (
              <Tooltip title={t('Update')}>
                <span>
                  <IconButton
                    aria-label="update"
                    disabled={
                      numberOfSelectedElements === 0
                      || processing
                    }
                    onClick={handleOpenUpdate}
                    size="small"
                  >
                    <BrushOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            )}
            {isUserDatatable && isEnterpriseEdition && (
              <UserEmailSend
                isOpen={displaySendEmail}
                onClose={handleCloseSendEmail}
                onSubmit={handleSubmitEmailTemplate}
              />
            )}
            {!removeAuthMembersEnabled && !removeFromDraftEnabled && !isInDraft && !isUserDatatable && !typesAreNotScannable && (
              <Tooltip title={t(isRuleEngineEnabled ? 'Rule rescan' : 'Rule rescan (engine is disabled)')}>
                <span>
                  <IconButton
                    aria-label="update"
                    disabled={!isRuleEngineEnabled || numberOfSelectedElements === 0 || processing}
                    onClick={handleOpenRescan}
                    size="small"
                  >
                    <AutoFixHighOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            )}
            {handleCopy && (
              <Tooltip title={titleCopy}>
                <span>
                  <IconButton
                    aria-label="copy"
                    disabled={
                      numberOfSelectedElements
                      > maxNumberOfObservablesToCopy
                    }
                    onClick={handleCopy}
                    size="small"
                  >
                    <ContentCopyOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            )}
            {!removeAuthMembersEnabled && !isUserDatatable && (
              <Tooltip title={t('Enrichment')}>
                <span>
                  <IconButton
                    aria-label="enrichment"
                    disabled={processing || enrichDisable}
                    onClick={() => handleOpenEnrichment(stixCyberObservableSubTypes, stixDomainObjectSubTypes)}
                    size="small"
                  >
                    <CloudRefreshOutline fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            )}
            {promoteEnabled && (
              <Tooltip title={t('Indicators/observables generation')}>
                <span>
                  <IconButton
                    aria-label="promote"
                    disabled={processing}
                    onClick={handleOpenPromote}
                    size="small"
                  >
                    <TransformOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            )}
          </Security>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNMERGE]}>
            {enableMerge && !removeAuthMembersEnabled && !removeFromDraftEnabled && !isInDraft && !isUserDatatable && (
              <Tooltip title={t('Merge')}>
                <span>
                  <IconButton
                    aria-label="merge"
                    disabled={
                      typesAreDifferent
                      || numberOfSelectedElements < 2
                      || numberOfSelectedElements > 4
                      || preventMerge
                      || selectAll
                      || processing
                    }
                    onClick={handleOpenMerge}
                    size="small"
                  >
                    <MergeOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            )}
          </Security>
          {!typesAreNotAddableInContainer && !removeAuthMembersEnabled && !isUserDatatable && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <Tooltip title={t('Add in container')}>
                <span>
                  <IconButton
                    aria-label="input"
                    disabled={
                      numberOfSelectedElements === 0
                      || processing
                    }
                    onClick={handleOpenAddInContainer}
                    size="small"
                  >
                    <MoveToInboxOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            </Security>
          )}
          {container && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <Tooltip title={t('Remove from the container')}>
                <span>
                  <IconButton
                    aria-label="remove"
                    disabled={
                      numberOfSelectedElements === 0
                      || processing
                    }
                    onClick={handleLaunchRemove}
                    size="small"
                  >
                    <LinkOffOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            </Security>
          )}
          {!trashOperationsEnabled && isShareableType && !removeAuthMembersEnabled && !isUserDatatable && (
            <>
              <Security needs={[KNOWLEDGE_KNUPDATE_KNORGARESTRICT]}>
                <EETooltip title={t('Share with organizations')}>
                  <IconButton
                    aria-label="input"
                    onClick={isEnterpriseEdition ? handleOpenShare : null}
                    size="small"
                    disabled={
                      numberOfSelectedElements === 0
                      || processing
                    }
                  >
                    <BankPlus fontSize="small" color={isEnterpriseEdition ? 'primary' : 'disabled'} />
                  </IconButton>
                </EETooltip>
              </Security>
              <Security needs={[KNOWLEDGE_KNUPDATE_KNORGARESTRICT]}>
                <EETooltip title={t('Unshare with organizations')}>
                  <IconButton
                    aria-label="input"
                    onClick={isEnterpriseEdition ? handleOpenUnshare : null}
                    size="small"
                    disabled={
                      numberOfSelectedElements === 0
                      || processing
                    }
                  >
                    <BankMinus fontSize="small" color={isEnterpriseEdition ? 'primary' : 'disabled'} />
                  </IconButton>
                </EETooltip>
              </Security>
            </>
          )}
          {!isInDraft
            && (!taskScope || taskScope === 'KNOWLEDGE')
            && !disableBulkEnroll
            && (
              <Security needs={[AUTOMATION]}>
                <Tooltip title={t('Enroll in playbook')}>
                  <span>
                    <IconButton
                      aria-label="enroll-playbook"
                      disabled={numberOfSelectedElements === 0 || processing}
                      onClick={handleOpenEnrollPlaybook}
                      size="small"
                    >
                      <PrecisionManufacturingOutlined fontSize="small" />
                    </IconButton>
                  </span>
                </Tooltip>
              </Security>
            )}
          {deleteDisable !== true && !removeAuthMembersEnabled && !removeFromDraftEnabled && !isUserDatatable && (
            <Security needs={[deleteCapability]}>
              <Tooltip title={warningMessage || t('Delete')}>
                <span>
                  <IconButton
                    aria-label="delete"
                    disabled={
                      numberOfSelectedElements === 0
                      || processing
                      || selectedElementsList.find((element) => element.currentUserAccessRight === 'view')
                    }
                    onClick={handleLaunchDelete}
                    color={warning ? 'error' : 'primary'}
                    size="small"
                  >
                    <DeleteOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            </Security>
          )}
          {removeFromDraftEnabled && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <Tooltip title={t('Remove from draft')}>
                <IconButton
                  color="primary"
                  aria-label="input"
                  onClick={handleLaunchRemoveFromDraft}
                  size="small"
                  disabled={
                    numberOfSelectedElements === 0
                    || processing
                  }
                >
                  <DeleteSweepOutlined fontSize="small" color="primary" />
                </IconButton>
              </Tooltip>
            </Security>
          )}
          {trashOperationsEnabled && (
            <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
              <Tooltip title={warningMessage || t('Restore')}>
                <span>
                  <IconButton
                    aria-label="restore"
                    disabled={
                      numberOfSelectedElements === 0
                      || processing
                    }
                    onClick={handleLaunchRestore}
                    color={warning ? 'error' : 'primary'}
                    size="small"
                    keepMui
                  >
                    <RestoreOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
              <Tooltip title={warningMessage || t('Confirm delete')}>
                <span>
                  <IconButton
                    aria-label="completeDelete"
                    disabled={
                      numberOfSelectedElements === 0
                      || processing
                    }
                    onClick={handleLaunchCompleteDelete}
                    color={warning ? 'error' : 'primary'}
                    size="small"
                    keepMui
                  >
                    <DeleteOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            </Security>
          )}
        </div>
      </Toolbar>
      <BackgroundTaskDialog
        open={displayTask}
        onClose={handleCloseTask}
        onLaunch={() => submitTask(availableFilterKeys, isInDraft)}
        processing={processing}
        numberOfSelectedElements={numberOfSelectedElements}
        selectAll={selectAll}
        search={search}
        filters={filters}
        entityTypes={entityTypes}
        selectedElementsList={selectedElementsList}
        mergingElement={mergingElement}
        actions={actions}
        customFieldDefinitions={customFieldDefinitions}
      />
      <BulkUpdateDrawer
        open={displayUpdate}
        onClose={handleCloseUpdate}
        onLaunch={handleLaunchUpdateSteps}
        selectedTypes={selectedTypes}
        entityTypeFilterValues={entityTypeFilterValues}
        contextTypes={[...(types ?? []), ...(type ? [type] : [])]}
        isAdmin={isAdmin}
        isUserDatatable={isUserDatatable}
        customFieldDefinitions={customFieldDefinitions}
        customFieldDefinitionsOfTypes={customFieldDefinitionsOfTypes}
        userStatuses={settings.platform_user_statuses}
        fetchUserOptions={fetchUserOptions}
      />
      <MergeDrawer
        open={displayMerge}
        onClose={() => setDisplayMerge(false)}
        elements={selectedElementsList}
        keptEntityId={keptEntityId}
        onKeptEntityIdChange={setKeptEntityId}
        onLaunch={handleLaunchMerge}
        noAuthor={noAuthor}
        noMarking={noMarking}
        noWarning={noWarning}
      />
      <EnrichmentDrawer
        open={displayEnrichment}
        onClose={() => setDisplayEnrichment(false)}
        connectors={enrichConnectors}
        onLaunch={handleLaunchEnrichment}
      />
      <PromoteDrawer
        isOpen={displayPromote}
        onClose={() => setDisplayPromote(false)}
        isOnlyStixCyberObservablesTypes={isOnlyStixCyberObservablesTypes}
        onSubmit={handleLaunchPromote}
        isContainer={isContainer}
        promoteToContainer={promoteToContainer}
        togglePromoteToContainer={() => setPromoteToContainer((current) => !current)}
      />
      <RuleRescanDrawer
        open={displayRescan}
        onClose={() => setDisplayRescan(false)}
        onLaunch={handleLaunchRescan}
      />
      <AddInContainerDialog
        open={displayAddInContainer}
        onClose={() => setDisplayAddInContainer(false)}
        step={addInContainerStep}
        onStepChange={setAddInContainerStep}
        onLaunch={handleLaunchAddInContainer}
      />
      <OrganizationSharingDialog
        mode="share"
        open={displayShare}
        onClose={() => setDisplayShare(false)}
        selected={shareOrganizations}
        onSelectedChange={setShareOrganizations}
        inputValue={organizationInput}
        onInputValueChange={setOrganizationInput}
        onLaunch={(organizations) => handleLaunchSharing('share', organizations)}
      />
      <OrganizationSharingDialog
        mode="unshare"
        open={displayUnshare}
        onClose={() => setDisplayUnshare(false)}
        selected={shareOrganizations}
        onSelectedChange={setShareOrganizations}
        inputValue={organizationInput}
        onInputValueChange={setOrganizationInput}
        onLaunch={(organizations) => handleLaunchSharing('unshare', organizations)}
      />
      <EnrollPlaybookDrawer
        open={displayEnrollPlaybook}
        onClose={() => setDisplayEnrollPlaybook(false)}
        onLaunch={handleLaunchEnrollPlaybook}
        entityIds={selectAll ? undefined : Object.keys(selectedElements || {})}
        isSelectAll={selectAll}
        filters={selectAll ? filters : undefined}
        search={selectAll ? search : undefined}
        excludedIds={selectAll ? Object.keys(deSelectedElements || {}) : undefined}
      />
    </>
  );
};

DataTableToolBar.propTypes = {
  numberOfSelectedElements: PropTypes.number,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
  filters: PropTypes.object,
  search: PropTypes.string,
  handleClearSelectedElements: PropTypes.func,
  variant: PropTypes.string,
  container: PropTypes.object,
  type: PropTypes.string,
  handleCopy: PropTypes.func,
  warning: PropTypes.bool,
  warningMessage: PropTypes.string,
  rightOffset: PropTypes.number,
  mergeDisable: PropTypes.bool,
  trashOperationsEnabled: PropTypes.bool,
  disableBulkEnroll: PropTypes.bool,
  removeAuthMembersEnabled: PropTypes.bool,
  removeFromDraft: PropTypes.bool,
  markAsReadEnabled: PropTypes.bool,
  taskScope: PropTypes.string,
};

export default DataTableToolBar;
