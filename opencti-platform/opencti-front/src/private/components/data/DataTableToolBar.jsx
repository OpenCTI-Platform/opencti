import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import {
  AddOutlined,
  AutoFixHighOutlined,
  BrushOutlined,
  CancelOutlined,
  CenterFocusStrong,
  CheckCircleOutlined,
  ClearOutlined,
  ContentCopyOutlined,
  DeleteOutlined,
  DeleteSweepOutlined,
  LanguageOutlined,
  LinkOffOutlined,
  LockOpenOutlined,
  MergeOutlined,
  MoveToInboxOutlined,
  PrecisionManufacturingOutlined,
  RestoreOutlined,
  TransformOutlined,
  UnpublishedOutlined,
} from '@mui/icons-material';
import { DialogContentText, FormControlLabel, Switch } from '@mui/material';
import Alert from '@mui/material/Alert';
import {
  Checkbox,
  Chip as FdsChip,
  Combobox,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '@filigran/design-system';
import Avatar from '@mui/material/Avatar';
import Chip from '@mui/material/Chip';
import DialogActions from '@mui/material/DialogActions';
import FormControl from '@mui/material/FormControl';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';

import Radio from '@mui/material/Radio';

import Slide from '@mui/material/Slide';
import MuiSwitch from '@mui/material/Switch';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TextField from '@mui/material/TextField';
import Toolbar from '@mui/material/Toolbar';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { BankMinus, BankPlus, CloudRefreshOutline, LabelOutline } from 'mdi-material-ui';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { ascend, map, path, pathOr, pipe, sortWith, union } from 'ramda';
import React, { Component } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import ItemIcon from '../../../components/ItemIcon';
import ItemMarkings from '../../../components/ItemMarkings';
import TasksFilterValueContainer from '../../../components/TasksFilterValueContainer';
import FormButtonContainer from '../../../components/common/form/FormButtonContainer';
import inject18n from '../../../components/i18n';
import { commitMutation, fetchQuery, MESSAGING$ } from '../../../relay/environment';
import { hexToRGB } from '../../../utils/Colors';
import Security from '../../../utils/Security';
import { EMPTY_VALUE, truncate } from '../../../utils/String';
import { getMainRepresentative } from '../../../utils/defaultRepresentatives';
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

import { externalReferencesQueriesSearchQuery } from '../analyses/external_references/ExternalReferencesQueries';
import Drawer from '../common/drawer/Drawer';
import EETooltip from '../common/entreprise_edition/EETooltip';
import { objectAssigneeFieldMembersSearchQuery } from '../common/form/ObjectAssigneeField';
import { objectMarkingFieldAllowedMarkingsQuery } from '../common/form/ObjectMarkingField';
import { objectParticipantFieldMembersSearchQuery } from '../common/form/ObjectParticipantField';
import { vocabularyQuery } from '../common/form/OpenVocabField';
import { statusFieldStatusesSearchQuery } from '../common/form/StatusField';
import { identitySearchIdentitiesSearchQuery } from '../common/identities/IdentitySearch';
import StixDomainObjectCreation from '../common/stix_domain_objects/StixDomainObjectCreation';
import { killChainPhasesSearchQuery } from '../settings/KillChainPhases';
import { labelsSearchQuery } from '../settings/LabelsQuery';
import UserEmailSend from '../settings/users/UserEmailSend';
import PromoteDrawer from './drawers/PromoteDrawer';

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
    height: 20,
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
    top: -20,
    right: -20,
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

const notMergableTypes = ['Playbook', 'Indicator', 'Note', 'Opinion', 'Label', 'Case-Template', 'Task', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace', 'DraftWorkspace', 'Notification'];
const notAddableTypes = ['Playbook', 'Label', 'Vocabulary', 'Case-Template', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace', 'DraftWorkspace', 'Notification'];
const notUpdatableTypes = ['Playbook', 'Label', 'Vocabulary', 'Case-Template', 'Task', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace', 'DraftWorkspace', 'Notification'];
const notScannableTypes = ['Playbook', 'Label', 'Vocabulary', 'Case-Template', 'Task', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace', 'DraftWorkspace', 'Notification'];
const notEnrichableTypes = ['Playbook', 'Label', 'Vocabulary', 'Case-Template', 'Task', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace', 'DraftWorkspace', 'Notification'];
const typesWithScore = [
  'Malware',
  'Stix-Cyber-Observable',
  'Indicator',
  'Autonomous-System',
  'Directory',
  'Domain-Name',
  'Email-Addr',
  'Email-Message',
  'Email-Mime-Part-Type',
  'StixFile',
  'X509-Certificate',
  'IPv4-Addr',
  'IPv6-Addr',
  'Mac-Addr',
  'Mutex',
  'Network-Traffic',
  'Process',
  'Software',
  'Url',
  'User-Account',
  'Windows-Registry-Key',
  'Windows-Registry-Value-Type',
  'Cryptographic-Key',
  'Cryptocurrency-Wallet',
  'Hostname',
  'Text',
  'Credential',
  'Tracking-Number',
  'User-Agent',
  'Bank-Account',
  'Phone-Number',
  'Payment-Card',
  'Media-Content',
  'Persona',
  'Threat-Actor-Group',
  'Intrusion-Set',
];
const typesWithSeverity = ['Case-Incident', 'Case-Rft', 'Case-Rfi'];
const typesWithPriority = ['Case-Incident', 'Case-Rft', 'Case-Rfi'];
const typesWithAssignee = ['Case-Incident', 'Case-Rft', 'Case-Rfi', 'Report'];
const typesWithParticipant = ['Case-Incident', 'Case-Rft', 'Case-Rfi', 'Report'];
const typesWithIncidentResponseType = ['Case-Incident'];
const typesWithRfiTypes = ['Case-Rfi'];
const typesWithRftTypes = ['Case-Rft'];
const typesWithDetection = ['Indicator'];
const typesWithKillChains = ['Indicator'];
const typesWithIndicatorTypes = ['Indicator'];
const typesWithPlatforms = ['Indicator'];
const typesWithTemporalRange = ['stix-core-relationship'];

const typesWithoutStatus = ['Stix-Core-Object', 'Stix-Domain-Object', 'Stix-Cyber-Observable', 'Artifact', 'ExternalReference'];
const notShareableTypes = ['Playbook', 'Label', 'Vocabulary', 'Case-Template', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace', 'DraftWorkspace', 'Notification'];

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

const toolBarContainersQuery = graphql`
  query DataTableToolBarContainersQuery($search: String) {
    containers(
      search: $search
      filters: {
        mode: and
        filters: [{ key: "entity_type", values: ["Container"] }]
        filterGroups: []
      }
    ) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

const toolBarOrganizationsQuery = graphql`
  query DataTableToolBarOrganizationsQuery($search: String) {
    organizations(search: $search) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

const toolbarGroupsQuery = graphql`
    query DataTableToolBarGroupsQuery($search: String) {
      groups(search: $search) {
        edges {
          node {
            id
            name
            entity_type
          }
        }
      }
    }
`;

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
      containerCreation: false,
      organizationCreation: false,
      actions: [],
      scope: undefined,
      actionsInputs: [{}],
      keptEntityId: null,
      mergingElement: null,
      description: '',
      processing: false,
      markingDefinitions: [],
      labels: [],
      identities: [],
      users: [],
      containers: [],
      organizations: [],
      statuses: [],
      externalReferences: [],
      enrichConnectors: [],
      enrichSelected: [],
      organizationInput: '',
      shareOrganizations: [],
      selectedCategory: '',
      vocabularies: {
        case_severity_ov: [],
        case_priority_ov: [],
        incident_response_types_ov: [],
        request_for_information_types_ov: [],
        request_for_takedown_types_ov: [],
        indicator_type_ov: [],
        platforms_ov: [],
      },
      navOpen: localStorage.getItem('navOpen') === 'true',
      assignees: [],
      participants: [],
      killChainPhases: [],
      groups: [],
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
    this.setState({ displayUpdate: false, actionsInputs: [{}] });
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
          enrichSelected: [],
        });
      });
  }

  handleCloseEnrichment() {
    this.setState({ displayEnrichment: false });
  }

  handleCloseMerge() {
    this.setState({ displayMerge: false });
  }

  handleAddStep() {
    this.setState({ actionsInputs: R.append({}, this.state.actionsInputs) });
  }

  handleRemoveStep(i) {
    const { actionsInputs } = this.state;
    actionsInputs.splice(i, 1);
    this.setState({ actionsInputs });
  }

  handleLaunchUpdate() {
    const { actionsInputs } = this.state;
    const categoryAttributeMapping = {
      case_severity_ov: 'severity',
      case_priority_ov: 'priority',
      incident_response_types_ov: 'response_types',
      request_for_information_types_ov: 'information_types',
      request_for_takedown_types_ov: 'takedown_types',
      indicator_type_ov: 'indicator_types',
      platforms_ov: 'x_mitre_platforms',
    };

    const actions = actionsInputs.map((n) => {
      if (categoryAttributeMapping[n.field]) {
        return ({
          type: n.type,
          context: {
            field: categoryAttributeMapping[n.field],
            type: n.fieldType,
            values: n.values.map((value) => value.label),
            options: n.options,
          },
        });
      }
      return {
        type: n.type,
        context: {
          field: n.field,
          type: n.fieldType,
          values: n.values,
          options: n.options,
        },
      };
    });
    this.setState({ actions }, () => {
      this.handleCloseUpdate();
      this.handleOpenTask();
    });
  }

  handleChangeActionInput(i, key, value) {
    const { actionsInputs } = this.state;
    const currentActionInput = actionsInputs[i] || {};

    actionsInputs[i] = R.assoc(key, value, currentActionInput);
    if (key === 'field') {
      if (value === 'x_opencti_detection') {
        actionsInputs[i] = R.assoc('values', ['false'], actionsInputs[i] || {});
      } else if (value === 'password_valid_until') {
        actionsInputs[i] = R.assoc('values', [new Date().toISOString()], actionsInputs[i] || {});
      } else if (['start_time', 'stop_time'].includes(value) && actionsInputs[i]?.type === 'REMOVE') {
        actionsInputs[i] = R.assoc('values', [''], actionsInputs[i] || {});
      } else {
        const values = [];
        actionsInputs[i] = R.assoc('values', values, actionsInputs[i] || {});
      }
      if (
        value === 'object-marking'
        || value === 'object-label'
        || value === 'created-by'
        || value === 'external-reference'
        || value === 'object-assignee'
        || value === 'object-participant'
      ) {
        actionsInputs[i] = R.assoc(
          'fieldType',
          'RELATION',
          actionsInputs[i] || {},
        );
      } else {
        actionsInputs[i] = R.assoc(
          'fieldType',
          'ATTRIBUTE',
          actionsInputs[i] || {},
        );
      }
    }
    this.setState({ actionsInputs });
  }

  // Event moved last and made optional: the library reports the DOM event on
  // ComboboxChangeMeta rather than as a positional first argument. The
  // stopPropagation stays — this toolbar sits over clickable table rows.
  handleChangeActionInputValues(i, value, event) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'values',
      Array.isArray(value) ? value : [value],
      actionsInputs[i] || {},
    );
    this.setState({ actionsInputs });
  }

  handleChangeActionInputOptions(i, key, checked) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'options',
      R.assoc(key, checked === true, actionsInputs[i]?.options || {}),
      actionsInputs[i] || {},
    );
    this.setState({ actionsInputs });
  }

  handleChangeActionInputValuesReplace(i, event) {
    const { value } = event.target;
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'values',
      Array.isArray(value) ? value : [value],
      actionsInputs[i] || {},
    );
    this.setState({ actionsInputs });
  }

  handleChangeSwitchInput(i, key, value) {
    const { actionsInputs } = this.state;
    const currentValue = actionsInputs[i] ? actionsInputs[i][key] : null;
    if (key === 'values' && currentValue !== value) {
      actionsInputs[i] = { ...actionsInputs[i], [key]: [String(value)] };
    } else {
      actionsInputs[i] = { ...actionsInputs[i], [key]: value };
    }
    this.setState({ actionsInputs });
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

  handleChangeKeptEntityId(entityId) {
    this.setState({ keptEntityId: entityId });
  }

  handleChangeEnrichSelected(connectorId) {
    if (this.state.enrichSelected.includes(connectorId)) {
      const filtered = this.state.enrichSelected.filter(
        (e) => e !== connectorId,
      );
      this.setState({ enrichSelected: filtered });
    } else {
      this.setState({
        enrichSelected: [...this.state.enrichSelected, connectorId],
      });
    }
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

  handleLaunchEnrichment() {
    const actions = [
      { type: 'ENRICHMENT', context: { values: this.state.enrichSelected } },
    ];
    this.setState({ actions }, () => {
      this.handleCloseEnrichment();
      this.handleOpenTask();
    });
  }

  handleLaunchMerge() {
    const { selectedElements } = this.props;
    const { keptEntityId } = this.state;
    const selectedElementsList = R.values(selectedElements);
    const keptElement = keptEntityId
      ? R.head(R.filter((n) => n.id === keptEntityId, selectedElementsList))
      : R.head(selectedElementsList);
    const filteredStixDomainObjects = keptEntityId
      ? R.filter((n) => n.id !== keptEntityId, selectedElementsList)
      : R.tail(selectedElementsList);
    const actions = [
      {
        type: 'MERGE',
        context: { values: filteredStixDomainObjects },
      },
    ];
    this.setState({ actions, mergingElement: keptElement }, () => {
      this.handleCloseMerge();
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

  static getActionType(type, field) {
    if (type === 'ADD' && field === 'groups') return 'ADD_GROUPS';
    if (type === 'ADD' && field === 'organizations') return 'ADD_ORGANIZATIONS';

    if (type === 'REMOVE' && field === 'groups') return 'REMOVE_GROUPS';
    if (type === 'REMOVE' && field === 'organizations') return 'REMOVE_ORGANIZATIONS';

    return type;
  }

  static normalizeActionValue(element) {
    if (element?.id) return element.id;
    if (element?.value) return element.value;
    if (typeof element?.toISOString === 'function') return element.toISOString();
    return element;
  }

  static displayActionValue(element) {
    if (typeof element === 'string') return element;
    if (typeof element?.toISOString === 'function') return element.toISOString();
    return getMainRepresentative(element);
  }

  getUserDatatableFinalActions(actions) {
    return actions.map((action) => {
      const currentType = this.constructor.getActionType(action.type, action.context.field);
      return {
        type: currentType,
        context: {
          ...action.context,
          values: action.context.values.map((element) => this.constructor.normalizeActionValue(element)),
        },
        containerId: null,
      };
    });
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

    const finalActions = taskScope === 'USER'
      ? this.getUserDatatableFinalActions(actions)
      : actions.map(
          (n) => ({
            type: n.type,
            context: n.context
              ? {
                  ...n.context,
                  values: n.context.values.map((o) => this.constructor.normalizeActionValue(o)),
                }
              : null,
            containerId: n.type === 'PROMOTE' && promoteToContainer && container?.id ? container.id : null,
          }),
        );

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

  renderFieldOptions(i, selectedTypes, entityTypeFilterValues, isAdmin) {
    const { t, taskScope } = this.props;
    const { actionsInputs } = this.state;

    const isUserDatatable = taskScope === 'USER';
    const disabled = actionsInputs[i]?.type == null || actionsInputs[i]?.type === '';
    const checkTypes = (typesList) => selectedTypes.every((type) => typesList.includes(type))
      && entityTypeFilterValues.every((type) => typesList.includes(type));
    const hasTemporalRangeField = entityTypeFilterValues.some((type) => typesWithTemporalRange.includes(type))
      || (this.props.types ?? []).some((type) => typesWithTemporalRange.includes(type))
      || typesWithTemporalRange.includes(this.props.type)
      || checkTypes(typesWithTemporalRange);

    let options = [];
    if (isUserDatatable) {
      if (['ADD', 'REMOVE'].includes(actionsInputs[i]?.type)) {
        options = [
          { label: t('Organizations'), value: 'organizations' },
          { label: t('Groups'), value: 'groups' },
        ];
      }
      if (actionsInputs[i]?.type === 'REPLACE') {
        options = [
          ...options,
          { label: t('Account status'), value: 'account_status' },
          { label: t('Account expiration date'), value: 'account_lock_after_date' },
          { label: t('Force password change date'), value: 'password_valid_until' },
        ].filter(Boolean);
      }
    } else {
      options = [
        { label: t('Marking definitions'), value: 'object-marking' },
        { label: t('Labels'), value: 'object-label' },
        checkTypes(typesWithAssignee) && { label: t('Assignees'), value: 'object-assignee' },
        checkTypes(typesWithParticipant) && { label: t('Participant'), value: 'object-participant' },
        ((actionsInputs[i]?.type === 'ADD' && isAdmin) || (actionsInputs[i]?.type === 'REPLACE' && isAdmin)) && {
          label: t('Creator'),
          value: 'creator_id',
        },
        (actionsInputs[i]?.type === 'ADD' || actionsInputs[i]?.type === 'REMOVE') && {
          label: t('External references'),
          value: 'external-reference',
        },
        checkTypes(typesWithKillChains) && (actionsInputs[i]?.type === 'ADD' || actionsInputs[i]?.type === 'REPLACE' || actionsInputs[i]?.type === 'REMOVE') && {
          label: t('Kill chains'),
          value: 'killChainPhases',
        },
        checkTypes(typesWithIndicatorTypes) && (actionsInputs[i]?.type === 'ADD' || actionsInputs[i]?.type === 'REPLACE' || actionsInputs[i]?.type === 'REMOVE') && {
          label: t('Indicator types'),
          value: 'indicator_type_ov',
        },
        checkTypes(typesWithPlatforms) && (actionsInputs[i]?.type === 'ADD' || actionsInputs[i]?.type === 'REPLACE' || actionsInputs[i]?.type === 'REMOVE') && {
          label: t('Platforms'),
          value: 'platforms_ov',
        },
        hasTemporalRangeField && (actionsInputs[i]?.type === 'ADD' || actionsInputs[i]?.type === 'REPLACE' || actionsInputs[i]?.type === 'REMOVE') && {
          label: t('Start time'),
          value: 'start_time',
        },
        hasTemporalRangeField && (actionsInputs[i]?.type === 'ADD' || actionsInputs[i]?.type === 'REPLACE' || actionsInputs[i]?.type === 'REMOVE') && {
          label: t('Stop time'),
          value: 'stop_time',
        },
        ...(actionsInputs[i]?.type === 'REPLACE' ? [
          { label: t('Author'), value: 'created-by' },
          { label: t('Confidence'), value: 'confidence' },
          { label: t('Description'), value: 'description' },
          checkTypes(typesWithSeverity) && { label: t('Severity'), value: 'case_severity_ov' },
          checkTypes(typesWithPriority) && { label: t('Priority'), value: 'case_priority_ov' },
          checkTypes(typesWithIncidentResponseType) && {
            label: t('Incident response type'),
            value: 'incident_response_types_ov',
          },
          checkTypes(typesWithRfiTypes) && {
            label: t('Request for information types'),
            value: 'request_for_information_types_ov',
          },
          checkTypes(typesWithRftTypes) && {
            label: t('Request for takedown types'),
            value: 'request_for_takedown_types_ov',
          },
          checkTypes(typesWithScore) && { label: t('Score'), value: 'x_opencti_score' },
          checkTypes(typesWithDetection) && { label: t('Detection'), value: 'x_opencti_detection' },
          selectedTypes.length === 1 && !typesWithoutStatus.includes(selectedTypes[0]) && {
            label: t('Status'),
            value: 'x_opencti_workflow_id',
          },
        ] : []),
      ].filter(Boolean);
    }

    const sortedOptions = options.sort((a, b) => a.label.localeCompare(b.label));

    const selectedFields = actionsInputs.map((a) => a.field).filter(Boolean);
    const replaceSelectedFields = actionsInputs.filter((a) => a.type === 'REPLACE').map((a) => a.field).filter(Boolean);

    return (
      <Select
        disabled={disabled}
        value={actionsInputs[i]?.type ?? ''}
        onValueChange={this.handleChangeActionInput.bind(this, i, 'field')}
      >
        <SelectLabel>{t('Field')}</SelectLabel>
        <SelectTrigger className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent aria-label={t('Field')}>
          {sortedOptions.length > 0 ? (
            sortedOptions.map(
              (n) => {
              // disable some fields to prevent making several actions on the same key if one of them is a replace
                const disableField = (replaceSelectedFields.includes(n.value) && actionsInputs[i]?.field !== n.value)
                  || (selectedFields.includes(n.value) && actionsInputs[i]?.type === 'REPLACE');
                return (
                  <SelectItem
                    key={n.value}
                    value={n.value}
                    disabled={disableField}
                  >
                    {n.label}
                  </SelectItem>
                );
              },
            )
          ) : (
            <SelectItem value="none">{t('None')}</SelectItem>
          )}
        </SelectContent>
      </Select>
    );
  }

  searchContainers(i, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });
    fetchQuery(toolBarContainersQuery, {
      search: newValue && newValue.length > 0 ? newValue : '',
    })
      .toPromise()
      .then((data) => {
        const elements = data.containers.edges.map((e) => e.node);
        const containers = elements
          .map((n) => ({
            label: n.representative.main,
            type: n.entity_type,
            value: n.id,
          }))
          .sort((a, b) => a.label.localeCompare(b.label))
          .sort((a, b) => a.type.localeCompare(b.type));
        this.setState({ containers });
      });
  }

  fetchOrganizations(newValue) {
    fetchQuery(toolBarOrganizationsQuery, {
      search: newValue && newValue.length > 0 ? newValue : '',
    })
      .toPromise()
      .then((data) => {
        const elements = data.organizations.edges.map((e) => e.node);
        const organizations = elements
          .map((n) => ({
            label: n.representative.main,
            type: n.entity_type,
            value: n.id,
          }))
          .sort((a, b) => a.label.localeCompare(b.label))
          .sort((a, b) => a.type.localeCompare(b.type));
        this.setState({ organizations });
      });
  }

  searchGroups(i, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });

    fetchQuery(toolbarGroupsQuery, {
      search: newValue && newValue.length > 0 ? newValue : '',
    })
      .toPromise()
      .then((data) => {
        const elements = data.groups.edges.map((e) => e.node);
        const groups = elements.map((element) => ({
          label: element.name,
          type: element.entity_type,
          value: element.id,
        }))
          .sort((a, b) => a.label.localeCompare(b.label))
          .sort((a, b) => a.type.localeCompare(b.type));
        this.setState({ groups });
      });
  }

  searchActionInputOrganizations(i, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });
    this.fetchOrganizations(newValue);
  }

  searchOrganizations(newValue) {
    this.setState({ organizationInput: newValue && newValue.length > 0 ? newValue : '' });
    this.fetchOrganizations(newValue);
  }

  searchMarkingDefinitions(i, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });
    fetchQuery(objectMarkingFieldAllowedMarkingsQuery)
      .toPromise()
      .then((data) => {
        const markingDefinitions = (data?.me?.allowed_marking ?? [])
          .map((n) => ({
            label: n.definition,
            value: n.id,
            color: n.x_opencti_color,
          }))
          .sort((a, b) => a.label.localeCompare(b.label));
        this.setState({ markingDefinitions });
      });
  }

  searchLabels(i, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });
    fetchQuery(labelsSearchQuery, {
      search: newValue && newValue.length > 0 ? newValue : '',
    })
      .toPromise()
      .then((data) => {
        const labels = (data?.labels?.edges ?? [])
          .map((n) => ({
            label: n.node.value,
            value: n.node.id,
            color: n.node.color,
          }))
          .sort((a, b) => a.label.localeCompare(b.label));
        this.setState({
          labels: R.union(this.state.labels, labels),
        });
      });
  }

  searchExternalReferences(i, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });
    fetchQuery(externalReferencesQueriesSearchQuery, {
      search: newValue && newValue.length > 0 ? newValue : '',
    })
      .toPromise()
      .then((data) => {
        const externalReferences = (data?.externalReferences?.edges ?? [])
          .map((n) => ({
            label: `[${n.node.source_name}] ${truncate(
              n.node.description || n.node.external_id,
              150,
            )} ${n.node.url && `(${n.node.url})`}`,
            value: n.node.id,
          }))
          .sort((a, b) => a.label.localeCompare(b.label));
        this.setState({
          externalReferences: R.union(
            this.state.externalReferences,
            externalReferences,
          ),
        });
      });
  }

  searchIdentities(i, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });
    fetchQuery(identitySearchIdentitiesSearchQuery, {
      types: ['Individual', 'Organization', 'System'],
      search: newValue && newValue.length > 0 ? newValue : '',
      first: 100,
    })
      .toPromise()
      .then((data) => {
        const identities = (data?.identities?.edges ?? [])
          .map((n) => ({
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
          }))
          .sort((a, b) => a.label.localeCompare(b.label))
          .sort((a, b) => a.type.localeCompare(b.type));
        this.setState({
          identities: R.union(this.state.identities, identities),
        });
      });
  }

  searchAccountStatus(i, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });
  }

  searchStatuses(i, selectedTypes, newValue) {
    const { actionsInputs } = this.state;
    let selectedType;
    if (selectedTypes.length === 1) {
      [selectedType] = selectedTypes;
    } else {
      throw Error('It is not possible to bulk edit statuses if more than one entity type is selected.');
    }
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });
    fetchQuery(statusFieldStatusesSearchQuery, {
      first: 100,
      filters: {
        mode: 'and',
        filterGroups: [],
        filters: [{ key: 'type', values: [selectedType] }],
      },
      orderBy: 'order',
      orderMode: 'asc',
      search: newValue && newValue.length > 0 ? newValue : '',
    })
      .toPromise()
      .then((data) => {
        const statuses = (data?.statuses?.edges ?? [])
          .map((n) => ({
            label: n.node.template.name,
            value: n.node.id,
            order: n.node.order,
            color: n.node.template.color,
          }))
          .sort((a, b) => a.label.localeCompare(b.label))
          .sort((a, b) => a.order - b.order);
        this.setState({ statuses: R.union(this.state.statuses, statuses) });
      });
  }

  searchVocabulary(i, category, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });
    fetchQuery(vocabularyQuery, {
      category,
      orderBy: 'name',
      orderMode: 'asc',
    })
      .toPromise()
      .then((data) => {
        const vocabularies = (data.vocabularies.edges ?? []).map((n) => ({
          label: n.node.name,
          value: n.node.id,
        }));
        this.setState((prevState) => ({
          vocabularies: R.assoc(
            category,
            R.union(prevState.vocabularies[category] || [], vocabularies),
            prevState.vocabularies,
          ),
        }));
      });
  }

  searchParticipants(i, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = {
      ...actionsInputs[i],
      inputValue: newValue && newValue.length > 0 ? newValue : '',
    };
    this.setState({ actionsInputs });
    fetchQuery(objectParticipantFieldMembersSearchQuery, {
      search: newValue && newValue.length > 0 ? newValue : '',
      entityTypes: ['User'],
      first: 10,
    })
      .toPromise()
      .then((data) => {
        const participants = (data.members?.edges ?? []).map((n) => ({
          label: n.node.name,
          value: n.node.id,
          type: n.node.entity_type,
        })).sort((a, b) => a.label.localeCompare(b.label));
        this.setState({
          participants: R.union(this.state.participants, participants),
        });
      });
  }

  searchAssignees(i, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = {
      ...actionsInputs[i],
      inputValue: newValue && newValue.length > 0 ? newValue : '',
    };
    this.setState({ actionsInputs });
    fetchQuery(objectAssigneeFieldMembersSearchQuery, {
      search: newValue && newValue.length > 0 ? newValue : '',
      entityTypes: ['User'],
      first: 10,
    })
      .toPromise()
      .then((data) => {
        const assignees = pipe(
          pathOr([], ['members', 'edges']),
          map((n) => ({
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
            entity: n.node,
          })),
        )(data);
        this.setState({
          assignees: R.union(this.state.assignees, assignees),
        });
      });
  }

  searchUsers(i, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });
    fetchQuery(toolBarUsersLinesSearchQuery, {
      search: newValue && newValue.length > 0 ? newValue : '',
      first: 100,
    })
      .toPromise()
      .then((data) => {
        const users = (data?.users?.edges ?? [])
          .map((n) => ({
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
          }))
          .sort((a, b) => a.label.localeCompare(b.label))
          .sort((a, b) => a.type.localeCompare(b.type));
        this.setState({
          users: R.union(this.state.users, users),
        });
      });
  }

  searchKillChains(i, newValue) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = {
      ...actionsInputs[i],
      inputValue: newValue && newValue.length > 0 ? newValue : '',
    };
    this.setState({ actionsInputs });
    fetchQuery(killChainPhasesSearchQuery, {
      search: newValue && newValue.length > 0 ? newValue : '',
    })
      .toPromise()
      .then((data) => {
        const killChainPhases = pipe(
          pathOr([], ['killChainPhases', 'edges']),
          sortWith([ascend(path(['node', 'x_opencti_order']))]),
          map((n) => ({
            label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
            value: n.node.id,
          })),
        )(data);
        this.setState({
          killChainPhases: union(this.state.killChainPhases, killChainPhases),
        });
      });
  }

  static getUserStatusOptionList(userStatuses) {
    return userStatuses.map((userStatus) => ({
      label: userStatus.status,
      value: userStatus.status,
    }));
  }

  handleChangeDate(i, newValue) {
    const { actionsInputs } = this.state;
    if (actionsInputs[i]?.type === 'REMOVE' && ['start_time', 'stop_time'].includes(actionsInputs[i]?.field)) {
      return;
    }
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });
  }

  handleAcceptDate(i, newValue) {
    const { actionsInputs } = this.state;
    if (actionsInputs[i]?.type === 'REMOVE' && ['start_time', 'stop_time'].includes(actionsInputs[i]?.field)) {
      return;
    }
    actionsInputs[i] = R.assoc(
      'values',
      Array.isArray(newValue) ? newValue : [newValue],
      actionsInputs[i] || {},
    );
    this.setState({ actionsInputs });
  }

  renderValuesOptions(i, selectedTypes, userStatuses) {
    const { t, classes } = this.props;

    const { actionsInputs } = this.state;

    const selectedField = actionsInputs[i]?.field;
    const disabled = selectedField == null || selectedField === '';

    switch (selectedField) {
      case 'container-object':
        return (
          <>
            <StixDomainObjectCreation
              inputValue={actionsInputs[i]?.inputValue || ''}
              open={this.state.containerCreation}
              display={true}
              speeddial={true}
              stixDomainObjectTypes={['Container']}
              handleClose={() => this.setState({ containerCreation: false })}
              creationCallback={(data) => {
                const element = {
                  label: data.name,
                  value: data.id,
                  type: data.entity_type,
                };
                this.setState(({ containers }) => ({
                  containers: [...(containers ?? []), element],
                }));
                this.handleChangeActionInputValues(i, [
                  ...(actionsInputs[i]?.values ?? []),
                  element,
                ]);
              }}
            />
            <Combobox
              disabled={disabled}
              selectOnFocus={true}
              getOptionLabel={(option) => option.label ?? ''}
              value={actionsInputs[i]?.values || []}
              multiple={true}
              // This panel opens inside the mass-edit dialog and is long enough to
              // overlay the dialog's own Update button. The library keeps a multi-value
              // panel open after each pick (documented `closeOnSelect` default false in
              // multiple mode) where MUI closed it, so the action becomes unreachable.
              // Measured: elementFromPoint at the button centre returns an option row.
              closeOnSelect
              options={this.state.containers}
              inputValue={actionsInputs[i]?.inputValue || ''}
              onInputChange={(newValue, meta) => {
                // Keystroke only. MUI reported an input change for every reason, which
                // is why every one of these searches opened with `if (!event) return`.
                if (meta.cause === 'type') (this.searchContainers.bind(this, i))(newValue);
              }}
              onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
              renderOption={(option) => (
                <>
                  <div className={classes.icon}>
                    <ItemIcon type={option.type} />
                  </div>
                  <div className={classes.text}>{option.label}</div>
                </>
              )}
            >
              <ComboboxLabel>{t('Values')}</ComboboxLabel>
              <ComboboxField>
                <ComboboxChips aria-label={t('Values')} />
                <ComboboxInput onFocus={() => (this.searchContainers.bind(this, i))('')} />
                <ComboboxControls>
                  <ComboboxClear />
                  <ComboboxTrigger />
                </ComboboxControls>
              </ComboboxField>
              <ComboboxContent
                emptyMessage={t('No available options')}
                listAriaLabel={t('Values')}
              />
            </Combobox>
            <IconButton
              aria-label={t('Create')}
              onClick={() => this.setState({ containerCreation: true })}
              edge="end"
              style={{ position: 'absolute', top: 80, right: 50 }}
            >
              <AddOutlined />
            </IconButton>
          </>
        );
      case 'object-marking':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            multiple={true}
            // This panel opens inside the mass-edit dialog and is long enough to
            // overlay the dialog's own Update button. The library keeps a multi-value
            // panel open after each pick (documented `closeOnSelect` default false in
            // multiple mode) where MUI closed it, so the action becomes unreachable.
            // Measured: elementFromPoint at the button centre returns an option row.
            closeOnSelect
            options={this.state.markingDefinitions}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchMarkingDefinitions.bind(this, i))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.icon} style={{ color: option.color }}>
                  <CenterFocusStrong />
                </div>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Values')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxChips aria-label={t('Values')} />
              <ComboboxInput onFocus={() => (this.searchMarkingDefinitions.bind(this, i))('')} />
              <ComboboxControls>
                <ComboboxClear />
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Values')}
            />
          </Combobox>
        );
      case 'object-label':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            multiple={true}
            // This panel opens inside the mass-edit dialog and is long enough to
            // overlay the dialog's own Update button. The library keeps a multi-value
            // panel open after each pick (documented `closeOnSelect` default false in
            // multiple mode) where MUI closed it, so the action becomes unreachable.
            // Measured: elementFromPoint at the button centre returns an option row.
            closeOnSelect
            options={this.state.labels}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchLabels.bind(this, i))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.icon} style={{ color: option.color }}>
                  <LabelOutline />
                </div>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Values')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxChips aria-label={t('Values')} />
              <ComboboxInput onFocus={() => (this.searchLabels.bind(this, i))('')} />
              <ComboboxControls>
                <ComboboxClear />
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Values')}
            />
          </Combobox>
        );
      case 'created-by':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values[0] || []}
            options={this.state.identities}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchIdentities.bind(this, i))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.icon}>
                  <ItemIcon type={option.type} />
                </div>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Values')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxInput onFocus={() => (this.searchIdentities.bind(this, i))('')} />
              <ComboboxControls>
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Values')}
            />
          </Combobox>
        );
      case 'x_opencti_workflow_id':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values[0] || []}
            options={this.state.statuses}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchStatuses.bind(this, i, selectedTypes))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.icon}>
                  <Avatar
                    variant="square"
                    style={{
                      color: option.color,
                      borderColor: option.color,
                      backgroundColor: hexToRGB(option.color),
                    }}
                  >
                    {option.order}
                  </Avatar>
                </div>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Values')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxInput onFocus={() => (this.searchStatuses.bind(this, i, selectedTypes))('')} />
              <ComboboxControls>
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Values')}
            />
          </Combobox>
        );
      case 'external-reference':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            multiple={true}
            // This panel opens inside the mass-edit dialog and is long enough to
            // overlay the dialog's own Update button. The library keeps a multi-value
            // panel open after each pick (documented `closeOnSelect` default false in
            // multiple mode) where MUI closed it, so the action becomes unreachable.
            // Measured: elementFromPoint at the button centre returns an option row.
            closeOnSelect
            options={this.state.externalReferences}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchExternalReferences.bind(this, i))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.icon} style={{ color: option.color }}>
                  <LanguageOutlined />
                </div>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Values')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxChips aria-label={t('Values')} />
              <ComboboxInput onFocus={() => (this.searchExternalReferences.bind(this, i))('')} />
              <ComboboxControls>
                <ComboboxClear />
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Values')}
            />
          </Combobox>
        );
      case 'object-assignee':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            multiple={true}
            // This panel opens inside the mass-edit dialog and is long enough to
            // overlay the dialog's own Update button. The library keeps a multi-value
            // panel open after each pick (documented `closeOnSelect` default false in
            // multiple mode) where MUI closed it, so the action becomes unreachable.
            // Measured: elementFromPoint at the button centre returns an option row.
            closeOnSelect
            options={this.state.assignees}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchAssignees.bind(this, i))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.icon}>
                  <ItemIcon type={option.type} />
                </div>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Values')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxChips aria-label={t('Values')} />
              <ComboboxInput onFocus={() => (this.searchAssignees.bind(this, i))('')} />
              <ComboboxControls>
                <ComboboxClear />
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Values')}
            />
          </Combobox>
        );
      case 'object-participant':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            multiple={true}
            // This panel opens inside the mass-edit dialog and is long enough to
            // overlay the dialog's own Update button. The library keeps a multi-value
            // panel open after each pick (documented `closeOnSelect` default false in
            // multiple mode) where MUI closed it, so the action becomes unreachable.
            // Measured: elementFromPoint at the button centre returns an option row.
            closeOnSelect
            options={this.state.participants}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchParticipants.bind(this, i))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.icon}>
                  <ItemIcon type={option.type} />
                </div>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Values')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxChips aria-label={t('Values')} />
              <ComboboxInput onFocus={() => (this.searchParticipants.bind(this, i))('')} />
              <ComboboxControls>
                <ComboboxClear />
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Values')}
            />
          </Combobox>
        );
      case 'case_severity_ov':
      case 'case_priority_ov':
      case 'incident_response_types_ov':
      case 'request_for_information_types_ov':
      case 'request_for_takedown_types_ov':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values[0] || null}
            options={this.state.vocabularies[selectedField] || []}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchVocabulary.bind(this, i, selectedField))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Select Value')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxInput onFocus={() => (this.searchVocabulary.bind(this, i, selectedField))('')} />
              <ComboboxControls>
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Select Value')}
            />
          </Combobox>
        );
      case 'indicator_type_ov':
      case 'platforms_ov':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || null}
            multiple={true}
            // This panel opens inside the mass-edit dialog and is long enough to
            // overlay the dialog's own Update button. The library keeps a multi-value
            // panel open after each pick (documented `closeOnSelect` default false in
            // multiple mode) where MUI closed it, so the action becomes unreachable.
            // Measured: elementFromPoint at the button centre returns an option row.
            closeOnSelect
            options={this.state.vocabularies[selectedField] || []}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchVocabulary.bind(this, i, selectedField))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Select Value')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxChips aria-label={t('Select Value')} />
              <ComboboxInput onFocus={() => (this.searchVocabulary.bind(this, i, selectedField))('')} />
              <ComboboxControls>
                <ComboboxClear />
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Select Value')}
            />
          </Combobox>
        );
      case 'creator_id':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values[0] || []}
            options={this.state.users}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchUsers.bind(this, i))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.icon}>
                  <ItemIcon type={option.type} />
                </div>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Values')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxInput onFocus={() => (this.searchUsers.bind(this, i))('')} />
              <ComboboxControls>
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Values')}
            />
          </Combobox>
        );
      case 'x_opencti_score':
      case 'confidence':
        return (
          <TextField
            variant="outlined"
            disabled={disabled}
            label={t('Values')}
            fullWidth={true}
            type="number"
            onChange={this.handleChangeActionInputValuesReplace.bind(this, i)}
          />
        );
      case 'killChainPhases':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            multiple={true}
            // This panel opens inside the mass-edit dialog and is long enough to
            // overlay the dialog's own Update button. The library keeps a multi-value
            // panel open after each pick (documented `closeOnSelect` default false in
            // multiple mode) where MUI closed it, so the action becomes unreachable.
            // Measured: elementFromPoint at the button centre returns an option row.
            closeOnSelect
            options={this.state.killChainPhases}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchKillChains.bind(this, i))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.icon} style={{ color: option.color }}>
                  <ItemIcon type="Kill-Chain-Phase" />
                </div>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Values')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxChips aria-label={t('Values')} />
              <ComboboxInput onFocus={() => (this.searchKillChains.bind(this, i))('')} />
              <ComboboxControls>
                <ComboboxClear />
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Values')}
            />
          </Combobox>
        );
      case 'x_opencti_detection':
        return (
          <FormControlLabel
            control={(
              <Switch
                onChange={(event) => this.handleChangeSwitchInput(i, 'values', event.target.checked)}
                name={`actions-${i}-value`}
                color="primary"
              />
            )}
            label={t('Value')}
          />
        );
      case 'organizations':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            multiple={true}
            // This panel opens inside the mass-edit dialog and is long enough to
            // overlay the dialog's own Update button. The library keeps a multi-value
            // panel open after each pick (documented `closeOnSelect` default false in
            // multiple mode) where MUI closed it, so the action becomes unreachable.
            // Measured: elementFromPoint at the button centre returns an option row.
            closeOnSelect
            options={this.state.organizations}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchActionInputOrganizations.bind(this, i))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.icon}>
                  <ItemIcon type={option.type} />
                </div>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Values')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxChips aria-label={t('Values')} />
              <ComboboxInput onFocus={() => (this.searchActionInputOrganizations.bind(this, i))('')} />
              <ComboboxControls>
                <ComboboxClear />
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Values')}
            />
          </Combobox>
        );
      case 'groups':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            multiple={true}
            // This panel opens inside the mass-edit dialog and is long enough to
            // overlay the dialog's own Update button. The library keeps a multi-value
            // panel open after each pick (documented `closeOnSelect` default false in
            // multiple mode) where MUI closed it, so the action becomes unreachable.
            // Measured: elementFromPoint at the button centre returns an option row.
            closeOnSelect
            options={this.state.groups}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchGroups.bind(this, i))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.icon}>
                  <ItemIcon type={option.type} />
                </div>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Values')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxChips aria-label={t('Values')} />
              <ComboboxInput onFocus={() => (this.searchGroups.bind(this, i))('')} />
              <ComboboxControls>
                <ComboboxClear />
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Values')}
            />
          </Combobox>
        );
      case 'account_status':
        return (
          <Combobox
            disabled={disabled}
            selectOnFocus={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values[0] || []}
            options={this.constructor.getUserStatusOptionList(userStatuses)}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onInputChange={(newValue, meta) => {
              // Keystroke only. MUI reported an input change for every reason, which
              // is why every one of these searches opened with `if (!event) return`.
              if (meta.cause === 'type') (this.searchAccountStatus.bind(this, i))(newValue);
            }}
            onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, i))(next, meta.event)}
            renderOption={(option) => (
              <>
                <div className={classes.text}>{option.label}</div>
              </>
            )}
          >
            <ComboboxLabel>{t('Values')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxInput />
              <ComboboxControls>
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent
              emptyMessage={t('No available options')}
              listAriaLabel={t('Values')}
            />
          </Combobox>
        );
      case 'account_lock_after_date':
        return (
          <DateTimePicker
            disabled={disabled}
            variant="inline"
            disableToolbar={false}
            autoOk={true}
            allowKeyboardControl={true}
            onChange={this.handleChangeDate.bind(this, i)}
            onAccept={this.handleAcceptDate.bind(this, i)}
            views={['year', 'month', 'day', 'hours', 'minutes', 'seconds']}
            format="yyyy-MM-dd hh:mm:ss a"
          />
        );
      case 'start_time':
      case 'stop_time':
        return (
          <DateTimePicker
            disabled={disabled || (actionsInputs[i]?.type === 'REMOVE' && ['start_time', 'stop_time'].includes(selectedField))}
            variant="inline"
            disableToolbar={false}
            autoOk={true}
            allowKeyboardControl={true}
            onChange={this.handleChangeDate.bind(this, i)}
            onAccept={this.handleAcceptDate.bind(this, i)}
            views={['year', 'month', 'day', 'hours', 'minutes', 'seconds']}
            format="yyyy-MM-dd hh:mm:ss a"
          />
        );
      case 'password_valid_until':
        return (
          <>
            <DateTimePicker
              variant="inline"
              disableToolbar={false}
              autoOk={true}
              allowKeyboardControl={true}
              onChange={this.handleChangeDate.bind(this, i)}
              onAccept={this.handleAcceptDate.bind(this, i)}
              views={['year', 'month', 'day', 'hours', 'minutes', 'seconds']}
              format="yyyy-MM-dd hh:mm:ss a"
            />
          </>
        );
      default:
        return (
          <TextField
            variant="outlined"
            disabled={disabled}
            label={t('Values')}
            fullWidth={true}
            onChange={this.handleChangeActionInputValuesReplace.bind(this, i)}
          />
        );
    }
  }

  areStepValid() {
    const { actionsInputs } = this.state;
    for (const n of actionsInputs) {
      if (!n || !n.type || !n.field || !n.values || n.values.length === 0) {
        return false;
      }
    }
    return true;
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
      n,
      classes,
      numberOfSelectedElements,
      handleClearSelectedElements,
      selectedElements,
      selectAll,
      filters,
      search,
      theme,
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
      keptEntityId,
      mergingElement,
      actionsInputs,
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
          const typesAreNotUpdatable = notUpdatableTypes.includes(selectedTypes[0])
            || (entityTypeFilterValues.length === 1
              && notUpdatableTypes.includes(entityTypeFilterValues[0]));
          // endregion
          // region rules
          const typesAreNotScannable = notScannableTypes.includes(selectedTypes[0])
            || (entityTypeFilterValues.length === 1
              && notScannableTypes.includes(entityTypeFilterValues[0]));
          // endregion
          // region enrich
          const isManualEnrichSelect = !selectAll && (selectedTypes.filter((st) => !['Stix-Cyber-Observable', 'Stix-Domain-Object'].includes(st))).length === 1;
          const isAllEnrichSelect = selectAll
            && entityTypeFilterValues.length === 1
            && entityTypeFilterValues[0] !== 'Stix-Cyber-Observable'
            && entityTypeFilterValues[0] !== 'Stix-Domain-Object';
          const enrichDisable = notEnrichableTypes.includes(selectedTypes[0])
            || (entityTypeFilterValues.length === 1
              && notEnrichableTypes.includes(entityTypeFilterValues[0]))
            || (!isManualEnrichSelect && !isAllEnrichSelect);
          // endregion
          // region orgaSharing
          const isShareableType = !notShareableTypes.includes(selectedTypes[0]);
          // endregion
          // region merge
          const typesAreNotMergable = notMergableTypes.includes(selectedTypes[0]);
          const enableMerge = !typesAreNotMergable && !mergeDisable;
          const typesAreNotAddableInContainer = notAddableTypes.includes(selectedTypes[0])
            || (entityTypeFilterValues.length === 1
              && notScannableTypes.includes(entityTypeFilterValues[0]));
          const titleCopy = this.titleCopy();
          let keptElement = null;
          let newAliases = [];
          if (!typesAreNotMergable && !typesAreDifferent) {
            keptElement = keptEntityId
              ? selectedElementsList.find((o) => o.id === keptEntityId)
              : selectedElementsList[0];
            if (keptElement) {
              const names = selectedElementsList
                .map((el) => el.name)
                .filter((name) => name !== keptElement.name);
              const aliases = keptElement.aliases !== null
                ? selectedElementsList
                    .map((el) => el.aliases)
                    .flat()
                    .filter((alias) => alias !== null && alias !== undefined)
                : selectedElementsList
                    .map((el) => el.x_opencti_aliases)
                    .flat()
                    .filter((alias) => alias !== null && alias !== undefined);

              newAliases = names.concat(aliases).filter((o) => o && o.length > 0);
            }
          }
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
              <Toolbar style={{ minHeight: 40, display: 'flex', justifyContent: 'space-between', height: '100%', paddingRight: 12, paddingLeft: 8 }} data-testid="opencti-toolbar">
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
                  <div>
                    {markAsReadEnabled && (
                      <>
                        <Tooltip title={t('Mark as read')}>
                          <span>
                            <IconButton
                              aria-label={t('Mark as read')}
                              disabled={numberOfSelectedElements === 0 || this.state.processing}
                              onClick={this.handleLaunchRead.bind(this, true)}
                              color="success"
                              size="small"
                            >
                              <CheckCircleOutlined />
                            </IconButton>
                          </span>
                        </Tooltip>
                        <Tooltip title={t('Mark as unread')}>
                          <span>
                            <IconButton
                              aria-label={t('Mark as unread')}
                              disabled={numberOfSelectedElements === 0 || this.state.processing}
                              onClick={this.handleLaunchRead.bind(this, false)}
                              color="error"
                              size="small"
                            >
                              <UnpublishedOutlined />
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
                              keepMui
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
              <Dialog
                open={this.state.displayTask}
                onClose={this.handleCloseTask.bind(this)}
                data-testid="background-task-popup"
                title={t('Launch a background task')}
              >
                <DialogContentText>
                  {`${n(numberOfSelectedElements)} ${t('selected element(s)')}`}
                </DialogContentText>
                {numberOfSelectedElements > 1000 && (
                  <Alert severity="warning">
                    {t(
                      'You\'re targeting more than 1000 entities with this background task, be sure of what you\'re doing!',
                    )}
                  </Alert>
                )}
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>#</TableCell>
                        <TableCell>{t('Step')}</TableCell>
                        <TableCell>{t('Field')}</TableCell>
                        <TableCell>{t('Values')}</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      <TableRow>
                        <TableCell>
                          {' '}
                          <span
                            style={{
                              padding: '2px 5px 2px 5px',
                              marginRight: 5,
                              color:
                                  theme.palette.mode === 'dark'
                                    ? '#000000'
                                    : '#ffffff',
                              backgroundColor: theme.palette.primary.main,
                            }}
                          >
                            1
                          </span>
                        </TableCell>
                        <TableCell>
                          <FdsChip label="SCOPE" />
                        </TableCell>
                        <TableCell>{t('N/A')}</TableCell>
                        <TableCell>
                          {selectAll ? (
                            <div className={classes.filters}>
                              {search && search.length > 0 && (
                                <span>
                                  <Chip
                                    classes={{ root: classes.filter }}
                                    label={(
                                      <div>
                                        <strong>{t('Search')}</strong>: {search}
                                      </div>
                                    )}
                                  />
                                  {filters.filters.length > 0 && (
                                    <FdsChip label={t('AND')} />
                                  )}
                                </span>
                              )}
                              <TasksFilterValueContainer filters={filters} entityTypes={entityTypes} />
                            </div>
                          ) : (
                            <span>
                              {mergingElement
                                ? truncate(
                                    R.join(', ', [
                                      getMainRepresentative(mergingElement),
                                    ]),
                                    80,
                                  )
                                : truncate(
                                    selectedElementsList.map((o) => getMainRepresentative(o)).join(', '),
                                    80,
                                  )}
                            </span>
                          )}
                        </TableCell>
                      </TableRow>
                      {R.map((o) => {
                        const number = actions.indexOf(o);
                        return (
                          <TableRow key={o.type}>
                            <TableCell>
                              {' '}
                              <span
                                style={{
                                  padding: '2px 5px 2px 5px',
                                  marginRight: 5,
                                  color:
                                      theme.palette.mode === 'dark'
                                        ? '#000000'
                                        : '#ffffff',
                                  backgroundColor: theme.palette.primary.main,
                                }}
                              >
                                {number + 2}
                              </span>
                            </TableCell>
                            <TableCell>
                              <FdsChip label={o.type} />
                            </TableCell>
                            <TableCell>
                              {R.pathOr(t('N/A'), ['context', 'field'], o)}
                            </TableCell>
                            <TableCell>
                              {truncate(
                                R.join(
                                  ', ',
                                  R.map(
                                    (p) => this.constructor.displayActionValue(p),
                                    R.pathOr([], ['context', 'values'], o),
                                  ),
                                ),
                                80,
                              )}
                            </TableCell>
                          </TableRow>
                        );
                      }, actions)}
                    </TableBody>
                  </Table>
                </TableContainer>
                <DialogActions>
                  <Button
                    variant="secondary"
                    onClick={this.handleCloseTask.bind(this)}
                    disabled={this.state.processing}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    onClick={this.submitTask.bind(this, availableFilterKeys, isInDraft)}
                    disabled={this.state.processing}
                  >
                    {t('Launch')}
                  </Button>
                </DialogActions>
              </Dialog>
              <Drawer
                title={t('Update entities')}
                open={this.state.displayUpdate}
                onClose={this.handleCloseUpdate.bind(this)}
              >
                <div>
                  {Array(actionsInputs.length)
                    .fill(0)
                    .map((item, i) => (
                      <div key={i} className={classes.step}>
                        <IconButton
                          disabled={actionsInputs.length === 1}
                          aria-label="Delete"
                          className={classes.stepCloseButton}
                          onClick={this.handleRemoveStep.bind(this, i)}
                          size="small"
                        >
                          <CancelOutlined fontSize="small" />
                        </IconButton>
                        <Grid container={true} spacing={3}>
                          <Grid item xs={3}>
                            <FormControl className={classes.formControl}>
                              <Select
                                value={actionsInputs[i]?.type ?? ''}
                                onValueChange={this.handleChangeActionInput.bind(
                                  this,
                                  i,
                                  'type',
                                )}
                              >
                                <SelectLabel>{t('Action type')}</SelectLabel>
                                <SelectTrigger className="w-full">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent aria-label={t('Action type')}>
                                  <SelectItem value="ADD">{t('Add')}</SelectItem>
                                  <SelectItem value="REPLACE">
                                    {t('Replace')}
                                  </SelectItem>
                                  <SelectItem value="REMOVE">{t('Remove')}</SelectItem>
                                </SelectContent>
                              </Select>
                            </FormControl>
                          </Grid>
                          <Grid item xs={3}>
                            <FormControl className={classes.formControl}>
                              {this.renderFieldOptions(i, selectedTypes, entityTypeFilterValues, isAdmin)}
                            </FormControl>
                          </Grid>
                          <Grid item xs={6} style={{ display: 'flex', flexDirection: 'column-reverse' }}>
                            {this.renderValuesOptions(i, selectedTypes, settings.platform_user_statuses)}
                          </Grid>
                          {['start_time', 'stop_time'].includes(actionsInputs[i]?.field) && actionsInputs[i]?.type !== 'REMOVE' && (
                            <Grid item xs={12}>
                              <Alert
                                severity="info"
                                variant="outlined"
                              >
                                {t('The "start time" must be earlier than the "stop time".')}
                              </Alert>
                            </Grid>
                          )}
                        </Grid>
                      </div>
                    ))}
                  <div className={classes.add}>
                    <IconButton
                      aria-label={t('Add step')}
                      disabled={!this.areStepValid()}
                      variant="secondary"
                      size="small"
                      onClick={this.handleAddStep.bind(this)}
                      classes={{ root: classes.buttonAdd }}
                    >
                      <AddOutlined fontSize="small" />
                    </IconButton>
                  </div>
                  <FormButtonContainer>
                    <Button
                      disabled={!this.areStepValid()}
                      onClick={this.handleLaunchUpdate.bind(this)}
                      classes={{ root: classes.button }}
                    >
                      {t('Update')}
                    </Button>
                  </FormButtonContainer>
                </div>
              </Drawer>
              <Drawer
                title={t('Merge entities')}
                open={this.state.displayMerge}
                onClose={this.handleCloseMerge.bind(this)}
              >
                <div>
                  <Typography
                    variant="h4"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Selected entities')}
                  </Typography>
                  <List>
                    {selectedElementsList.map((element) => (
                      <ListItem
                        key={element.id}
                        dense={true}
                        divider={true}
                        secondaryAction={(
                          <Radio
                            checked={
                              keptEntityId
                                ? keptEntityId === element.id
                                : R.head(selectedElementsList).id === element.id
                            }
                            onChange={this.handleChangeKeptEntityId.bind(
                              this,
                              element.id,
                            )}
                            value={element.id}
                            name="keptEntityID"
                            inputProps={{ 'aria-label': 'keptEntityID' }}
                          />
                        )}
                      >
                        <ListItemIcon>
                          <ItemIcon type={element.entity_type} />
                        </ListItemIcon>
                        <ListItemText
                          sx={{
                            '.MuiListItemText-primary': {
                              overflowX: 'hidden',
                              textOverflow: 'ellipsis',
                            },
                          }}
                          primary={getMainRepresentative(element)}
                          secondary={truncate(
                            element.description
                            || element.x_opencti_description
                            || '',
                            60,
                          )}
                        />
                        <div style={{ marginRight: 50 }}>
                          {element.createdBy?.name ?? EMPTY_VALUE}
                        </div>
                        <div style={{ marginRight: 50 }}>
                          <ItemMarkings
                            variant="inList"
                            markingDefinitions={element.objectMarking ?? []}
                          />
                        </div>
                      </ListItem>
                    ))}
                  </List>
                  <Typography
                    variant="h4"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Merged entity')}
                  </Typography>
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Name')}
                  </Typography>
                  <div style={{ overflowX: 'hidden', textOverflow: 'ellipsis' }}>
                    {getMainRepresentative(keptElement)}
                  </div>
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Aliases')}
                  </Typography>
                  {newAliases.map((label) => (label.length > 0 ? (
                    <FdsChip key={label} label={label} />
                  ) : (
                    ''
                  )))}
                  {noAuthor !== true && (
                    <>
                      <Typography
                        variant="h3"
                        gutterBottom={true}
                        style={{ marginTop: 20 }}
                      >
                        {t('Author')}
                      </Typography>
                      {keptElement?.createdBy?.name ?? EMPTY_VALUE}
                    </>
                  )}
                  {noMarking !== true && (
                    <>
                      <Typography
                        variant="h3"
                        gutterBottom={true}
                        style={{ marginTop: 20 }}
                      >
                        {t('Marking')}
                      </Typography>
                      <ItemMarkings
                        markingDefinitions={keptElement?.objectMarking || []}
                      />
                    </>
                  )}
                  {noWarning !== true && (
                    <>
                      <Alert severity="warning" style={{ marginTop: 20 }}>
                        {t(
                          'The relations attached to selected entities will be copied to the merged entity.',
                        )}
                      </Alert>
                    </>
                  )}
                  <FormButtonContainer>
                    <Button
                      onClick={this.handleLaunchMerge.bind(this)}
                    >
                      {t('Merge')}
                    </Button>
                  </FormButtonContainer>
                </div>
              </Drawer>
              <Drawer
                title={t('Entity enrichment')}
                open={this.state.displayEnrichment}
                onClose={this.handleCloseEnrichment.bind(this)}
              >
                <div>
                  <Typography
                    variant="h4"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Selected connectors')}
                  </Typography>
                  <List>
                    {this.state.enrichConnectors.length === 0 && (
                      <Alert severity="warning">
                        {t('No connector available for the selected entities.')}
                      </Alert>
                    )}
                    {this.state.enrichConnectors.map((connector) => (
                      <ListItem
                        key={connector.id}
                        dense={true}
                        divider={true}
                        secondaryAction={(
                          <MuiSwitch
                            checked={this.state.enrichSelected.includes(
                              connector.id,
                            )}
                            onChange={this.handleChangeEnrichSelected.bind(
                              this,
                              connector.id,
                            )}
                            inputProps={{ 'aria-label': 'controlled' }}
                          />
                        )}
                      >
                        <ListItemIcon>
                          <CloudRefreshOutline />
                        </ListItemIcon>
                        <ListItemText primary={connector.name} />
                      </ListItem>
                    ))}
                  </List>
                  <FormButtonContainer>
                    <Button
                      disabled={
                        this.state.enrichConnectors.length === 0
                        || this.state.enrichSelected.length === 0
                      }
                      onClick={this.handleLaunchEnrichment.bind(this)}
                    >
                      {t('Enrich')}
                    </Button>
                  </FormButtonContainer>
                </div>
              </Drawer>
              <PromoteDrawer
                isOpen={this.state.displayPromote}
                onClose={this.handleClosePromote.bind(this)}
                isOnlyStixCyberObservablesTypes={isOnlyStixCyberObservablesTypes}
                onSubmit={this.handleLaunchPromote.bind(this)}
                isContainer={isContainer}
                promoteToContainer={promoteToContainer}
                togglePromoteToContainer={this.togglePromoteToContainer.bind(this)}
              />
              <Drawer
                title={t('Rule entity rescan')}
                open={this.state.displayRescan}
                onClose={this.handleCloseRescan.bind(this)}
              >
                <div>
                  <Typography
                    variant="h4"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Selected rules')}
                  </Typography>
                  <Alert severity="warning" style={{ marginTop: 20 }}>
                    {t(
                      'Element will be rescan with all compatible activated rules',
                    )}
                  </Alert>
                  <FormButtonContainer>
                    <Button
                      onClick={this.handleLaunchRescan.bind(this)}
                    >
                      {t('Rescan')}
                    </Button>
                  </FormButtonContainer>
                </div>
              </Drawer>
              <Dialog
                open={this.state.displayAddInContainer}
                onClose={() => this.setState({ displayAddInContainer: false })}
                title={t('Add in container')}
              >
                <StixDomainObjectCreation
                  inputValue={actionsInputs[0]?.inputValue || ''}
                  open={this.state.containerCreation}
                  display={true}
                  speeddial={true}
                  stixDomainObjectTypes={['Container']}
                  handleClose={() => this.setState({ containerCreation: false })
                  }
                  creationCallback={(data) => {
                    const element = {
                      label: data.name,
                      value: data.id,
                      type: data.entity_type,
                    };
                    this.setState(({ containers }) => ({
                      containers: [...(containers ?? []), element],
                    }));
                    this.handleChangeActionInputValues(0, null, [
                      ...(actionsInputs[0]?.values ?? []),
                      element,
                    ]);
                  }}
                />
                <Combobox
                  selectOnFocus={true}
                  getOptionLabel={(option) => (option.label ? option.label : '')}
                  value={actionsInputs[0]?.values || []}
                  multiple={true}
                  // This panel opens inside the mass-edit dialog and is long enough to
                  // overlay the dialog's own Update button. The library keeps a multi-value
                  // panel open after each pick (documented `closeOnSelect` default false in
                  // multiple mode) where MUI closed it, so the action becomes unreachable.
                  // Measured: elementFromPoint at the button centre returns an option row.
                  closeOnSelect
                  options={this.state.containers}
                  inputValue={actionsInputs[0]?.inputValue || ''}
                  onInputChange={(newValue, meta) => {
                    // Keystroke only. MUI reported an input change for every reason, which
                    // is why every one of these searches opened with `if (!event) return`.
                    if (meta.cause === 'type') (this.searchContainers.bind(this, 0))(newValue);
                  }}
                  onValueChange={(next, meta) => (this.handleChangeActionInputValues.bind(this, 0))(next, meta.event)}
                  renderOption={(option) => (
                    <>
                      <div className={classes.icon}>
                        <ItemIcon type={option.type} />
                      </div>
                      <div className={classes.text}>{option.label}</div>
                    </>
                  )}
                  disableClearable
                >
                  <ComboboxLabel>{t('Values')}</ComboboxLabel>
                  <ComboboxField>
                    <ComboboxChips aria-label={t('Values')} />
                    <ComboboxInput onFocus={() => (this.searchContainers.bind(this, 0))('')} />
                    <ComboboxControls>
                      <ComboboxClear />
                      <ComboboxTrigger />
                    </ComboboxControls>
                  </ComboboxField>
                  <ComboboxContent
                    emptyMessage={t('No available options')}
                    listAriaLabel={t('Values')}
                  />
                </Combobox>
                <div style={{ marginTop: 20 }}>
                  <Checkbox
                    checked={
                      actionsInputs[0]?.options?.includeNeighbours || false
                    }
                    onCheckedChange={this.handleChangeActionInputOptions.bind(
                      this,
                      0,
                      'includeNeighbours',
                    )}
                    label={t('Also include first neighbours')}
                  />
                </div>
                <IconButton
                  aria-label={t('Create container')}
                  onClick={() => this.setState({ containerCreation: true })}
                  edge="end"
                  style={{ position: 'absolute', top: 80, right: 50 }}
                >
                  <AddOutlined />
                </IconButton>

                <DialogActions>
                  <Button
                    variant="secondary"
                    onClick={() => this.setState({ displayAddInContainer: false })
                    }
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    onClick={() => {
                      this.setState(
                        {
                          displayAddInContainer: false,
                          actionsInputs: [
                            {
                              ...actionsInputs[0],
                              type: 'ADD',
                              fieldType: 'ATTRIBUTE',
                              field: 'container-object',
                            },
                          ],
                        },
                        this.handleLaunchUpdate.bind(this),
                      );
                    }}
                  >
                    {t('Add')}
                  </Button>
                </DialogActions>
              </Dialog>
              <Dialog
                open={this.state.displayShare}
                onClose={() => this.setState({ displayShare: false })}
                title={t('Share with organizations')}
              >
                <StixDomainObjectCreation
                  inputValue={this.state.organizationInput}
                  open={this.state.organizationCreation}
                  display={true}
                  speeddial={true}
                  stixDomainObjectTypes={['Organization']}
                  handleClose={() => this.setState({ organizationCreation: false })}
                  creationCallback={(data) => {
                    const element = {
                      label: data.name,
                      value: data.id,
                      type: data.entity_type,
                    };
                    this.setState(({ organizations }) => ({
                      organizations: [...(organizations ?? []), element],
                    }));
                    this.setState({ shareOrganizations: [...this.state.shareOrganizations, element] });
                  }}
                />
                <Combobox
                  selectOnFocus={true}
                  getOptionLabel={(option) => (option.label ? option.label : '')}
                  value={this.state.shareOrganizations}
                  multiple={true}
                  // This panel opens inside the mass-edit dialog and is long enough to
                  // overlay the dialog's own Update button. The library keeps a multi-value
                  // panel open after each pick (documented `closeOnSelect` default false in
                  // multiple mode) where MUI closed it, so the action becomes unreachable.
                  // Measured: elementFromPoint at the button centre returns an option row.
                  closeOnSelect
                  options={this.state.organizations}
                  inputValue={this.state.organizationInput}
                  onInputChange={(newValue, meta) => {
                    // Keystroke only. MUI reported an input change for every reason, which
                    // is why every one of these searches opened with `if (!event) return`.
                    if (meta.cause === 'type') (this.searchOrganizations.bind(this))(newValue);
                  }}
                  onValueChange={(next, meta) => ((_, value) => this.setState({ shareOrganizations: value }))(next, meta.event)}
                  renderOption={(option) => (
                    <>
                      <div className={classes.icon}>
                        <ItemIcon type={option.type} />
                      </div>
                      <div className={classes.text}>{option.label}</div>
                    </>
                  )}
                  disableClearable
                >
                  <ComboboxLabel>{t('Values')}</ComboboxLabel>
                  <ComboboxField>
                    <ComboboxChips aria-label={t('Values')} />
                    <ComboboxInput onFocus={() => (this.searchOrganizations.bind(this))('')} />
                    <ComboboxControls>
                      <ComboboxClear />
                      <ComboboxTrigger />
                    </ComboboxControls>
                  </ComboboxField>
                  <ComboboxContent
                    emptyMessage={t('No available options')}
                    listAriaLabel={t('Values')}
                  />
                </Combobox>
                <IconButton
                  aria-label={t('Create organization')}
                  onClick={() => this.setState({ organizationCreation: true })}
                  edge="end"
                  style={{ position: 'absolute', top: 80, right: 50 }}
                >
                  <AddOutlined />
                </IconButton>
                <DialogActions>
                  <Button
                    variant="secondary"
                    onClick={this.handleCloseShare.bind(this)}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    onClick={() => {
                      const shareActions = [
                        { type: 'SHARE_MULTIPLE', context: { values: this.state.shareOrganizations } },
                      ];
                      const orgaNames = this.state.shareOrganizations.map((o) => o.label).join('|');
                      const sharingDescription = `SHARE with organizations ${orgaNames}`;
                      this.setState({ description: sharingDescription, actions: shareActions }, () => {
                        this.handleCloseShare();
                        this.handleOpenTask();
                      });
                    }}
                  >
                    {t('Share')}
                  </Button>
                </DialogActions>
              </Dialog>
              <Dialog
                open={this.state.displayUnshare}
                onClose={() => this.setState({ displayUnshare: false })}
                title={t('Unshare with organizations')}
              >
                <Combobox
                  selectOnFocus={true}
                  getOptionLabel={(option) => (option.label ? option.label : '')}
                  value={this.state.shareOrganizations}
                  multiple={true}
                  // This panel opens inside the mass-edit dialog and is long enough to
                  // overlay the dialog's own Update button. The library keeps a multi-value
                  // panel open after each pick (documented `closeOnSelect` default false in
                  // multiple mode) where MUI closed it, so the action becomes unreachable.
                  // Measured: elementFromPoint at the button centre returns an option row.
                  closeOnSelect
                  options={this.state.organizations}
                  inputValue={this.state.organizationInput}
                  onInputChange={(newValue, meta) => {
                    // Keystroke only. MUI reported an input change for every reason, which
                    // is why every one of these searches opened with `if (!event) return`.
                    if (meta.cause === 'type') (this.searchOrganizations.bind(this))(newValue);
                  }}
                  onValueChange={(next, meta) => ((_, value) => this.setState({ shareOrganizations: value }))(next, meta.event)}
                  renderOption={(option) => (
                    <>
                      <div className={classes.icon}>
                        <ItemIcon type={option.type} />
                      </div>
                      <div className={classes.text}>{option.label}</div>
                    </>
                  )}
                  disableClearable
                >
                  <ComboboxLabel>{t('Values')}</ComboboxLabel>
                  <ComboboxField>
                    <ComboboxChips aria-label={t('Values')} />
                    <ComboboxInput onFocus={() => (this.searchOrganizations.bind(this))('')} />
                    <ComboboxControls>
                      <ComboboxClear />
                      <ComboboxTrigger />
                    </ComboboxControls>
                  </ComboboxField>
                  <ComboboxContent
                    emptyMessage={t('No available options')}
                    listAriaLabel={t('Values')}
                  />
                </Combobox>
                <DialogActions>
                  <Button
                    variant="secondary"
                    onClick={this.handleCloseUnshare.bind(this)}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={() => {
                      const shareActions = [
                        { type: 'UNSHARE_MULTIPLE', context: { values: this.state.shareOrganizations } },
                      ];
                      const orgaNames = this.state.shareOrganizations.map((o) => o.label).join('|');
                      const sharingDescription = `UNSHARE with organizations ${orgaNames}`;
                      this.setState({ description: sharingDescription, actions: shareActions }, () => {
                        this.handleCloseUnshare();
                        this.handleOpenTask();
                      });
                    }}
                  >
                    {t('Unshare')}
                  </Button>
                </DialogActions>
              </Dialog>
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

export default R.compose(inject18n, withTheme, withStyles(styles))(DataTableToolBar);
