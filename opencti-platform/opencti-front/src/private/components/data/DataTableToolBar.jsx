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
import Slide from '@mui/material/Slide';
import Toolbar from '@mui/material/Toolbar';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import { BankMinus, BankPlus, CloudRefreshOutline } from 'mdi-material-ui';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import React, { Component } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import inject18n from '../../../components/i18n';
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

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  buttonAdd: {
    width: '100%',
    height: 36,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  aliases: {
    margin: '0 7px 7px 0',
  },
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
  chipValue: {
    margin: 0,
  },
  filter: {
    margin: '5px 10px 5px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '5px 10px 5px 0',
  },
  step: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.background.accent}`,
    borderRadius: 5,
    display: 'flex',
  },
  formControl: {
    width: '100%',
  },
  stepType: {
    margin: 0,
    paddingRight: 20,
    width: '30%',
  },
  stepField: {
    margin: 0,
    paddingRight: 20,
    width: '30%',
  },
  stepValues: {
    paddingRight: 20,
    margin: 0,
  },
  stepCloseButton: {
    position: 'absolute',
    top: 4,
    right: 4,
  },
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  noResult: {
    color: theme.palette.text.primary,
    fontSize: 15,
    textAlign: 'center',
    marginTop: 20,
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

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

class DataTableToolBar extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayTask: false,
      displayUpdate: false,
      displayEnrichment: false,
      displayRescan: false,
      displayMerge: false,
      displayAddInContainer: false,
      displayShare: false,
      displayUnshare: false,
      displayPromote: false,
      displayEnrollPlaybook: false,
      displaySendEmail: false,
      actions: [],
      scope: undefined,
      addInContainerStep: {},
      keptEntityId: null,
      mergingElement: null,
      description: '',
      processing: false,
      enrichConnectors: [],
      organizationInput: '',
      shareOrganizations: [],
      selectedCategory: '',
      navOpen: localStorage.getItem('navOpen') === 'true',
      displayEditButtons: true,
    };
  }

  componentDidMount() {
    this.subscription = MESSAGING$.toggleNav.subscribe({
      next: () => this.setState({ navOpen: localStorage.getItem('navOpen') === 'true' }),
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleOpenTask() {
    this.setState({ displayTask: true });
  }

  handleCloseTask() {
    this.setState({
      displayTask: false,
      actions: [],
      scope: undefined,
      keptEntityId: null,
      mergingElement: null,
      processing: false,
      description: '',
    });
  }

  handleOpenUpdate() {
    this.setState({ displayUpdate: true });
  }

  handleOpenRescan() {
    this.setState({ displayRescan: true });
  }

  handleCloseRescan() {
    this.setState({ displayRescan: false });
  }

  handleCloseUpdate() {
    // Kept from the steps shared with the update drawer: closing it also clears the container step
    this.setState({ displayUpdate: false, addInContainerStep: {} });
  }

  handleOpenMerge() {
    this.setState({ displayMerge: true });
  }

  handleOpenAddInContainer() {
    this.setState({ displayAddInContainer: true });
  }

  handleOpenShare() {
    this.setState({ displayShare: true });
  }

  handleCloseShare() {
    this.setState({ displayShare: false });
  }

  handleOpenUnshare() {
    this.setState({ displayUnshare: true });
  }

  handleCloseUnshare() {
    this.setState({ displayUnshare: false });
  }

  handleCloseSendEmail() {
    this.setState({ displaySendEmail: false });
  }

  handleOpenPromote() {
    this.setState({ displayPromote: true });
  }

  handleClosePromote() {
    this.setState({ displayPromote: false });
  }

  handleOpenEnrollPlaybook() {
    this.setState({ displayEnrollPlaybook: true });
  }

  handleCloseEnrollPlaybook() {
    this.setState({ displayEnrollPlaybook: false });
  }

  handleLaunchEnrollPlaybook(playbookId, playbookName) {
    const actions = [{
      type: 'ENROLL_PLAYBOOK',
      context: { values: [{ id: playbookId, name: playbookName }] },
    }];
    const description = `ENROLL IN PLAYBOOK ${playbookName}`;
    this.setState({ description, actions }, () => {
      this.handleCloseEnrollPlaybook();
      this.handleOpenTask();
    });
  }

  handleOpenEnrichment(stixCyberObservableSubTypes, stixDomainObjectSubTypes) {
    // Get enrich type
    let enrichType;
    const entityTypeFilterValues = getEntityTypeThreeFirstLevelsFilterValues(this.props.filters, stixCyberObservableSubTypes, stixDomainObjectSubTypes);
    if (this.props.selectAll) {
      enrichType = this.props.type ?? R.head(entityTypeFilterValues);
    } else {
      const selectedElementsList = Object.values(this.props.selectedElements || {});
      const selectedTypes = R.uniq(selectedElementsList
        .map((o) => o.entity_type)
        .filter((entity_type) => entity_type !== undefined));
      enrichType = R.head(selectedTypes);
    }
    // Get available connectors
    fetchQuery(toolBarConnectorsQuery, { type: enrichType })
      .toPromise()
      .then((data) => {
        this.setState({
          displayEnrichment: true,
          enrichConnectors: data.enrichmentConnectors ?? [],
        });
      });
  }

  handleCloseEnrichment() {
    this.setState({ displayEnrichment: false });
  }

  handleCloseMerge() {
    this.setState({ displayMerge: false });
  }

  // Event last and optional: the library reports it on ComboboxChangeMeta.
  handleLaunchAddInContainer() {
    const step = { ...this.state.addInContainerStep, type: 'ADD', fieldType: 'ATTRIBUTE', field: 'container-object' };
    const actions = buildUpdateActions([step]);
    this.setState({ displayAddInContainer: false, actions }, () => {
      this.handleCloseUpdate();
      this.handleOpenTask();
    });
  }

  handleLaunchUpdateSteps(steps) {
    const actions = buildUpdateActions(steps);
    this.setState({ actions }, () => {
      this.handleCloseUpdate();
      this.handleOpenTask();
    });
  }

  handleLaunchRead(read) {
    const actions = [{
      type: 'REPLACE',
      context: {
        field: 'is_read',
        type: 'ATTRIBUTE',
        values: [read ? 'true' : 'false'],
      },
    }];
    this.setState({ actions }, () => {
      this.handleOpenTask();
    });
  }

  handleLaunchDelete() {
    const actions = [{ type: 'DELETE', context: null }];
    this.setState({ actions }, () => {
      this.handleOpenTask();
    });
  }

  handleLaunchRemoveAuthMembers() {
    const actions = [{ type: 'REMOVE_AUTH_MEMBERS', context: null }];
    this.setState({ actions }, () => {
      this.handleOpenTask();
    });
  }

  handleLaunchRemoveFromDraft() {
    const actions = [{ type: 'REMOVE_FROM_DRAFT', context: null }];
    this.setState({ actions }, () => {
      this.handleOpenTask();
    });
  }

  handleLaunchRemove() {
    const actions = [
      {
        type: 'REMOVE',
        context: { field: 'container-object', values: [this.props.container] },
      },
    ];
    this.setState({ actions }, () => {
      this.handleOpenTask();
    });
  }

  handleLaunchCompleteDelete() {
    const actions = [{ type: 'COMPLETE_DELETE', context: null }];
    this.setState({ actions }, () => {
      this.handleOpenTask();
    });
  }

  handleLaunchRestore() {
    const actions = [{ type: 'RESTORE', context: null }];
    this.setState({ actions }, () => {
      this.handleOpenTask();
    });
  }

  handleLaunchRescan() {
    const actions = [{ type: 'RULE_ELEMENT_RESCAN' }];
    this.setState({ actions }, () => {
      this.handleCloseRescan();
      this.handleOpenTask();
    });
  }

  handleLaunchPromote() {
    const actions = [{ type: 'PROMOTE' }];
    this.setState({ actions }, () => {
      this.handleClosePromote();
      this.handleOpenTask();
    });
  }

  handleLaunchEnrichment(connectorIds) {
    const actions = [
      { type: 'ENRICHMENT', context: { values: connectorIds } },
    ];
    this.setState({ actions }, () => {
      this.handleCloseEnrichment();
      this.handleOpenTask();
    });
  }

  handleLaunchMerge(keptElement, mergedElements) {
    const actions = [
      {
        type: 'MERGE',
        context: { values: mergedElements },
      },
    ];
    this.setState({ actions, mergingElement: keptElement }, () => {
      this.handleCloseMerge();
      this.handleOpenTask();
    });
  }

  handleLaunchSharing(mode, organizations) {
    const actions = [
      { type: mode === 'share' ? 'SHARE_MULTIPLE' : 'UNSHARE_MULTIPLE', context: { values: organizations } },
    ];
    const orgaNames = organizations.map((o) => o.label).join('|');
    const description = `${mode === 'share' ? 'SHARE' : 'UNSHARE'} with organizations ${orgaNames}`;
    this.setState({ description, actions }, () => {
      if (mode === 'share') this.handleCloseShare();
      else this.handleCloseUnshare();
      this.handleOpenTask();
    });
  }

  titleCopy() {
    const { t } = this.props;
    if (this.props.numberOfSelectedElements > maxNumberOfObservablesToCopy) {
      return `${
        t(
          'Copy disabled: too many selected elements (maximum number of elements for a copy: ',
        ) + maxNumberOfObservablesToCopy
      })`;
    }
    return t('Copy to clipboard');
  }

  submitTask(availableFilterKeys, isInDraft) {
    this.setState({ processing: true });
    const { description, actions, mergingElement, promoteToContainer } = this.state;
    const {
      filters,
      search,
      selectAll,
      selectedElements,
      deSelectedElements,
      numberOfSelectedElements,
      handleClearSelectedElements,
      container,
      taskScope,
      t,
    } = this.props;
    const scope = taskScope ?? 'KNOWLEDGE';
    if (numberOfSelectedElements === 0) return;
    const jsonFilters = serializeFilterGroupForBackend(
      removeIdAndIncorrectKeysFromFilterGroupObject(filters, availableFilterKeys),
    );

    const finalActions = buildTaskActions(actions, { taskScope, promoteToContainer, containerId: container?.id });

    if (selectAll) {
      commitMutation({
        mutation: toolBarQueryTaskAddMutation,
        variables: {
          input: {
            description,
            filters: jsonFilters,
            search,
            actions: finalActions,
            excluded_ids: Object.keys(deSelectedElements || {}),
            scope,
          },
        },
        onCompleted: () => {
          handleClearSelectedElements();
          const monitoringLink = !isInDraft ? <Link to="/dashboard/data/processing/tasks">{t('the dedicated page')}</Link> : t('the draft processes tab');
          MESSAGING$.notifySuccess(
            <span>
              {t(
                'The background task has been executed. You can monitor it on',
              )}{' '}
              {monitoringLink}
              .
            </span>,
          );
          this.setState({ processing: false });
          this.handleCloseTask();
        },
      });
    } else {
      commitMutation({
        mutation: toolBarListTaskAddMutation,
        variables: {
          input: {
            description,
            ids: mergingElement
              ? [mergingElement.id]
              : Object.keys(selectedElements),
            actions: finalActions,
            scope,
          },
        },
        onCompleted: () => {
          handleClearSelectedElements();
          const monitoringLink = !isInDraft ? <Link to="/dashboard/data/processing/tasks">{t('the dedicated page')}</Link> : t('the draft processes tab');
          MESSAGING$.notifySuccess(
            <span>
              {t(
                'The background task has been executed. You can monitor it on',
              )}{' '}
              {monitoringLink}
              .
            </span>,
          );
          this.setState({ processing: false });
          this.handleCloseTask();
        },
      });
    }
  }

  togglePromoteToContainer() {
    this.setState((prevState) => ({ promoteToContainer: !prevState.promoteToContainer }));
  }

  getSelectedTypes(observableTypes, domainObjectTypes) {
    const entityTypeFilterValues = getEntityTypeThreeFirstLevelsFilterValues(this.props.filters, observableTypes, domainObjectTypes);
    const selectedElementsList = Object.values(this.props.selectedElements || {});
    const selectedTypes = R.uniq([...selectedElementsList.map((o) => o.entity_type), ...entityTypeFilterValues]
      .filter((entity_type) => entity_type !== undefined));
    return { entityTypeFilterValues, selectedElementsList, selectedTypes };
  }

  handleSubmitEmailTemplate(emailTemplate) {
    this.handleCloseSendEmail();
    const sendEmailAction = [
      {
        type: 'SEND_EMAIL',
        context: { values: [emailTemplate.id] },
      },
    ];
    this.setState({ actions: sendEmailAction }, () => {
      this.handleOpenTask();
    });
  }

  render() {
    const {
      t,
      classes,
      numberOfSelectedElements,
      handleClearSelectedElements,
      selectedElements,
      selectAll,
      filters,
      search,
      container,
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
    } = this.props;
    const {
      actions,
      mergingElement,
      promoteToContainer,
      displayEditButtons,
    } = this.state;
    const isUserDatatable = taskScope === 'USER';

    let deleteCapability = KNOWLEDGE_KNUPDATE_KNDELETE;
    if (taskScope === 'DASHBOARD') deleteCapability = EXPLORE_EXUPDATE_EXDELETE;
    if (taskScope === 'PUBLIC_DASHBOARD') deleteCapability = EXPLORE_EXUPDATE_PUBLISH;
    if (taskScope === 'INVESTIGATION') deleteCapability = INVESTIGATION_INUPDATE_INDELETE;

    return (
      <UserContext.Consumer>
        {({ schema, settings, me }) => {
          const isAdmin = me.capabilities.map((o) => o.name).filter((o) => [SETTINGS_SETACCESSES, BYPASS].includes(o)).length > 0;
          const isInDraft = me.draftContext;

          const stixCyberObservableSubTypes = schema.scos.map((sco) => sco.id);
          const stixDomainObjectSubTypes = schema.sdos.map((sdo) => sdo.id);
          const { entityTypeFilterValues, selectedElementsList, selectedTypes } = this.getSelectedTypes(stixCyberObservableSubTypes, stixDomainObjectSubTypes);
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
          const titleCopy = this.titleCopy();
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

          const entityTypes = selectedTypes.length > 0 ? selectedTypes : [this.props.type ?? 'Stix-Core-Object'];
          // Only the custom fields carried by every targeted type are offered
          const customFieldDefinitionsOfTypes = getCustomFieldDefinitionsOfTypes(
            this.props.customFieldDefinitions ?? [],
            getTaskTargetedTypes(selectAll, selectedElementsList, entityTypeFilterValues, this.props.types),
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
                      numberOfSelectedElements === 0 || this.state.processing
                    }
                    onClick={handleClearSelectedElements.bind(this)}
                  >
                    <ClearOutlined />
                  </IconButton>
                </div>
                {displayEditButtons && (
                  <div className={classes.editButtons}>
                    {markAsReadEnabled && (
                      <>
                        <Tooltip title={t('Mark as read')}>
                          <span>
                            <IconButton
                              aria-label={t('Mark as read')}
                              disabled={numberOfSelectedElements === 0 || this.state.processing}
                              onClick={this.handleLaunchRead.bind(this, true)}
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
                              disabled={numberOfSelectedElements === 0 || this.state.processing}
                              onClick={this.handleLaunchRead.bind(this, false)}
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
                            onClick={this.handleLaunchRemoveAuthMembers.bind(this)}
                            size="small"
                            disabled={
                              numberOfSelectedElements === 0
                              || this.state.processing
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
                                || this.state.processing
                              }
                              onClick={this.handleOpenUpdate.bind(this)}
                              size="small"
                            >
                              <BrushOutlined />
                            </IconButton>
                          </span>
                        </Tooltip>
                      )}
                      {isUserDatatable && isEnterpriseEdition && (
                        <UserEmailSend
                          isOpen={this.state.displaySendEmail}
                          onClose={this.handleCloseSendEmail.bind(this)}
                          onSubmit={this.handleSubmitEmailTemplate.bind(this)}
                        />
                      )}
                      {!removeAuthMembersEnabled && !removeFromDraftEnabled && !isInDraft && !isUserDatatable && (
                        <UserContext.Consumer>
                          {({ platformModuleHelpers }) => {
                            const label = platformModuleHelpers.isRuleEngineEnable()
                              ? 'Rule rescan'
                              : 'Rule rescan (engine is disabled)';
                            const buttonDisable = typesAreNotScannable
                              || !platformModuleHelpers.isRuleEngineEnable()
                              || numberOfSelectedElements === 0
                              || this.state.processing;
                            return typesAreNotScannable ? undefined : (
                              <Tooltip title={t(label)}>
                                <span>
                                  <IconButton
                                    aria-label="update"
                                    disabled={buttonDisable}
                                    onClick={this.handleOpenRescan.bind(this)}
                                    size="small"
                                  >
                                    <AutoFixHighOutlined />
                                  </IconButton>
                                </span>
                              </Tooltip>
                            );
                          }}
                        </UserContext.Consumer>
                      )}
                      {this.props.handleCopy && (
                        <Tooltip title={titleCopy}>
                          <span>
                            <IconButton
                              aria-label="copy"
                              disabled={
                                numberOfSelectedElements
                                > maxNumberOfObservablesToCopy
                              }
                              onClick={this.props.handleCopy}
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
                              disabled={this.state.processing || enrichDisable}
                              onClick={this.handleOpenEnrichment.bind(this, stixCyberObservableSubTypes, stixDomainObjectSubTypes)}
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
                              disabled={this.state.processing}
                              onClick={this.handleOpenPromote.bind(this)}
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
                                || this.state.processing
                              }
                              onClick={this.handleOpenMerge.bind(this)}
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
                                || this.state.processing
                              }
                              onClick={this.handleOpenAddInContainer.bind(this)}
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
                                || this.state.processing
                              }
                              onClick={this.handleLaunchRemove.bind(this)}
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
                              onClick={isEnterpriseEdition ? this.handleOpenShare.bind(this) : null}
                              size="small"
                              disabled={
                                numberOfSelectedElements === 0
                                || this.state.processing
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
                              onClick={isEnterpriseEdition ? this.handleOpenUnshare.bind(this) : null}
                              size="small"
                              disabled={
                                numberOfSelectedElements === 0
                                || this.state.processing
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
                                disabled={numberOfSelectedElements === 0 || this.state.processing}
                                onClick={this.handleOpenEnrollPlaybook.bind(this)}
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
                                || this.state.processing
                                || selectedElementsList.find((element) => element.currentUserAccessRight === 'view')
                              }
                              onClick={this.handleLaunchDelete.bind(this)}
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
                            onClick={this.handleLaunchRemoveFromDraft.bind(this)}
                            size="small"
                            disabled={
                              numberOfSelectedElements === 0
                              || this.state.processing
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
                                || this.state.processing
                              }
                              onClick={this.handleLaunchRestore.bind(this)}
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
                                || this.state.processing
                              }
                              onClick={this.handleLaunchCompleteDelete.bind(this)}
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
                )}
              </Toolbar>
              <BackgroundTaskDialog
                open={this.state.displayTask}
                onClose={this.handleCloseTask.bind(this)}
                onLaunch={this.submitTask.bind(this, availableFilterKeys, isInDraft)}
                processing={this.state.processing}
                numberOfSelectedElements={numberOfSelectedElements}
                selectAll={selectAll}
                search={search}
                filters={filters}
                entityTypes={entityTypes}
                selectedElementsList={selectedElementsList}
                mergingElement={mergingElement}
                actions={actions}
                customFieldDefinitions={this.props.customFieldDefinitions ?? []}
              />
              <BulkUpdateDrawer
                open={this.state.displayUpdate}
                onClose={this.handleCloseUpdate.bind(this)}
                onLaunch={this.handleLaunchUpdateSteps.bind(this)}
                selectedTypes={selectedTypes}
                entityTypeFilterValues={entityTypeFilterValues}
                contextTypes={[...(this.props.types ?? []), ...(this.props.type ? [this.props.type] : [])]}
                isAdmin={isAdmin}
                isUserDatatable={isUserDatatable}
                customFieldDefinitions={this.props.customFieldDefinitions ?? []}
                customFieldDefinitionsOfTypes={customFieldDefinitionsOfTypes}
                userStatuses={settings.platform_user_statuses}
                fetchUserOptions={fetchUserOptions}
              />
              <MergeDrawer
                open={this.state.displayMerge}
                onClose={this.handleCloseMerge.bind(this)}
                elements={selectedElementsList}
                keptEntityId={this.state.keptEntityId}
                onKeptEntityIdChange={(keptEntityId) => this.setState({ keptEntityId })}
                onLaunch={this.handleLaunchMerge.bind(this)}
                noAuthor={noAuthor}
                noMarking={noMarking}
                noWarning={noWarning}
              />
              <EnrichmentDrawer
                open={this.state.displayEnrichment}
                onClose={this.handleCloseEnrichment.bind(this)}
                connectors={this.state.enrichConnectors}
                onLaunch={this.handleLaunchEnrichment.bind(this)}
              />
              <PromoteDrawer
                isOpen={this.state.displayPromote}
                onClose={this.handleClosePromote.bind(this)}
                isOnlyStixCyberObservablesTypes={isOnlyStixCyberObservablesTypes}
                onSubmit={this.handleLaunchPromote.bind(this)}
                isContainer={isContainer}
                promoteToContainer={promoteToContainer}
                togglePromoteToContainer={this.togglePromoteToContainer.bind(this)}
              />
              <RuleRescanDrawer
                open={this.state.displayRescan}
                onClose={this.handleCloseRescan.bind(this)}
                onLaunch={this.handleLaunchRescan.bind(this)}
              />
              <AddInContainerDialog
                open={this.state.displayAddInContainer}
                onClose={() => this.setState({ displayAddInContainer: false })}
                step={this.state.addInContainerStep}
                onStepChange={(update) => this.setState(({ addInContainerStep }) => ({ addInContainerStep: update(addInContainerStep) }))}
                onLaunch={this.handleLaunchAddInContainer.bind(this)}
              />
              <OrganizationSharingDialog
                mode="share"
                open={this.state.displayShare}
                onClose={this.handleCloseShare.bind(this)}
                selected={this.state.shareOrganizations}
                onSelectedChange={(shareOrganizations) => this.setState({ shareOrganizations })}
                inputValue={this.state.organizationInput}
                onInputValueChange={(organizationInput) => this.setState({ organizationInput })}
                onLaunch={this.handleLaunchSharing.bind(this, 'share')}
              />
              <OrganizationSharingDialog
                mode="unshare"
                open={this.state.displayUnshare}
                onClose={this.handleCloseUnshare.bind(this)}
                selected={this.state.shareOrganizations}
                onSelectedChange={(shareOrganizations) => this.setState({ shareOrganizations })}
                inputValue={this.state.organizationInput}
                onInputValueChange={(organizationInput) => this.setState({ organizationInput })}
                onLaunch={this.handleLaunchSharing.bind(this, 'unshare')}
              />
              <EnrollPlaybookDrawer
                open={this.state.displayEnrollPlaybook}
                onClose={this.handleCloseEnrollPlaybook.bind(this)}
                onLaunch={this.handleLaunchEnrollPlaybook.bind(this)}
                entityIds={this.props.selectAll ? undefined : Object.keys(this.props.selectedElements || {})}
                isSelectAll={this.props.selectAll}
                filters={this.props.selectAll ? this.props.filters : undefined}
                search={this.props.selectAll ? this.props.search : undefined}
                excludedIds={this.props.selectAll ? Object.keys(this.props.deSelectedElements || {}) : undefined}
              />
            </>
          );
        }}
      </UserContext.Consumer>
    );
  }
}

DataTableToolBar.propTypes = {
  customFieldDefinitions: PropTypes.array,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
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

const DataTableToolBarComponent = R.compose(inject18n, withTheme, withStyles(styles))(DataTableToolBar);

// The update entities drawer offers the custom fields: their definitions are loaded once elements are selected
const DataTableToolBarWithCustomFields = (props) => {
  const customFieldDefinitions = useCustomFieldDefinitions(props.numberOfSelectedElements > 0);
  return <DataTableToolBarComponent {...props} customFieldDefinitions={customFieldDefinitions} />;
};

export default DataTableToolBarWithCustomFields;
