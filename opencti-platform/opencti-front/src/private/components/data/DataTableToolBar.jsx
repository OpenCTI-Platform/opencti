import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Toolbar from '@mui/material/Toolbar';
import MuiSwitch from '@mui/material/Switch';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import List from '@mui/material/List';
import Radio from '@mui/material/Radio';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Table from '@mui/material/Table';
import TableHead from '@mui/material/TableHead';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableRow from '@mui/material/TableRow';
import IconButton from '@mui/material/IconButton';
import {
  AddOutlined,
  AutoFixHighOutlined,
  BrushOutlined,
  CancelOutlined,
  CenterFocusStrong,
  ClearOutlined,
  CloseOutlined,
  ContentCopyOutlined,
  DeleteOutlined,
  LanguageOutlined,
  LinkOffOutlined,
  MergeOutlined,
  MoveToInboxOutlined,
  RestoreOutlined,
  TransformOutlined,
} from '@mui/icons-material';
import { BankMinus, BankPlus, CloudRefreshOutline, LabelOutline } from 'mdi-material-ui';
import Autocomplete from '@mui/material/Autocomplete';
import Drawer from '@mui/material/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide from '@mui/material/Slide';
import Chip from '@mui/material/Chip';
import DialogTitle from '@mui/material/DialogTitle';
import Alert from '@mui/material/Alert';
import TextField from '@mui/material/TextField';
import Grid from '@mui/material/Grid';
import Avatar from '@mui/material/Avatar';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import PromoteDrawer from './drawers/PromoteDrawer';
import TasksFilterValueContainer from '../../../components/TasksFilterValueContainer';
import inject18n from '../../../components/i18n';
import { truncate } from '../../../utils/String';
import { commitMutation, fetchQuery, MESSAGING$ } from '../../../relay/environment';
import ItemIcon from '../../../components/ItemIcon';
import { objectMarkingFieldAllowedMarkingsQuery } from '../common/form/ObjectMarkingField';
import { identitySearchIdentitiesSearchQuery } from '../common/identities/IdentitySearch';
import { labelsSearchQuery } from '../settings/LabelsQuery';
import Security from '../../../utils/Security';
import {
  EXPLORE_EXUPDATE_EXDELETE,
  EXPLORE_EXUPDATE_PUBLISH,
  INVESTIGATION_INUPDATE_INDELETE,
  KNOWLEDGE_KNUPDATE,
  KNOWLEDGE_KNUPDATE_KNDELETE,
  KNOWLEDGE_KNUPDATE_KNORGARESTRICT,
} from '../../../utils/hooks/useGranted';
import { UserContext } from '../../../utils/hooks/useAuth';
import { statusFieldStatusesSearchQuery } from '../common/form/StatusField';
import { hexToRGB } from '../../../utils/Colors';
import { externalReferencesQueriesSearchQuery } from '../analyses/external_references/ExternalReferencesQueries';
import StixDomainObjectCreation from '../common/stix_domain_objects/StixDomainObjectCreation';
import ItemMarkings from '../../../components/ItemMarkings';
import { findFilterFromKey, removeIdAndIncorrectKeysFromFilterGroupObject, serializeFilterGroupForBackend } from '../../../utils/filters/filtersUtils';
import { getMainRepresentative } from '../../../utils/defaultRepresentatives';
import { isNotEmptyField } from '../../../utils/utils';
import EETooltip from '../common/entreprise_edition/EETooltip';

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
});

const notMergableTypes = ['Indicator', 'Note', 'Opinion', 'Label', 'Case-Template', 'Task', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace'];
const notAddableTypes = ['Label', 'Vocabulary', 'Case-Template', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace'];
const notUpdatableTypes = ['Label', 'Vocabulary', 'Case-Template', 'Task', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace'];
const notScannableTypes = ['Label', 'Vocabulary', 'Case-Template', 'Task', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace'];
const notEnrichableTypes = ['Label', 'Vocabulary', 'Case-Template', 'Task', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace'];
const typesWithScore = ['Stix-Cyber-Observable', 'Indicator'];
const notShareableTypes = ['Label', 'Vocabulary', 'Case-Template', 'DeleteOperation', 'InternalFile', 'PublicDashboard', 'Workspace'];

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
      containerCreation: false,
      organizationCreation: false,
      actions: [],
      scope: undefined,
      actionsInputs: [{}],
      keptEntityId: null,
      mergingElement: null,
      processing: false,
      markingDefinitions: [],
      labels: [],
      identities: [],
      containers: [],
      organizations: [],
      statuses: [],
      externalReferences: [],
      enrichConnectors: [],
      enrichSelected: [],
      organizationInput: '',
      shareOrganizations: [],
      navOpen: localStorage.getItem('navOpen') === 'true',
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

  handleOpenPromote() {
    this.setState({ displayPromote: true });
  }

  handleClosePromote() {
    this.setState({ displayPromote: false });
  }

  handleOpenEnrichment() {
    // Get enrich type
    let enrichType;
    if (this.props.selectAll) {
      enrichType = this.props.type
        ?? R.head(
          findFilterFromKey(
            this.props.filters?.filters ?? [],
            'entity_type',
            'eq',
          )?.values ?? [],
        );
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
    const actions = R.map(
      (n) => ({
        type: n.type,
        context: {
          field: n.field,
          type: n.fieldType,
          values: n.values,
          options: n.options,
        },
      }),
      actionsInputs,
    );
    this.setState({ actions }, () => {
      this.handleCloseUpdate();
      this.handleOpenTask();
    });
  }

  handleChangeActionInput(i, key, event) {
    const { value } = event.target;
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(key, value, actionsInputs[i] || {});
    if (key === 'field') {
      const values = [];
      actionsInputs[i] = R.assoc('values', values, actionsInputs[i] || {});
      if (
        value === 'object-marking'
        || value === 'object-label'
        || value === 'created-by'
        || value === 'external-reference'
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

  handleChangeActionInputValues(i, event, value) {
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

  handleChangeActionInputOptions(i, key, event) {
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'options',
      R.assoc(key, event.target.checked, actionsInputs[i]?.options || {}),
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

  handleLaunchDelete() {
    const actions = [{ type: 'DELETE', context: null }];
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
    return t('Copy');
  }

  submitTask(availableFilterKeys) {
    this.setState({ processing: true });
    const { actions, mergingElement, promoteToContainer } = this.state;
    const {
      filters,
      search,
      selectAll,
      selectedElements,
      deSelectedElements,
      numberOfSelectedElements,
      handleClearSelectedElements,
      container,
      taskScope: scope = 'KNOWLEDGE',
      t,
    } = this.props;
    if (numberOfSelectedElements === 0) return;
    const jsonFilters = serializeFilterGroupForBackend(
      removeIdAndIncorrectKeysFromFilterGroupObject(filters, availableFilterKeys),
    );

    const finalActions = R.map(
      (n) => ({
        type: n.type,
        context: n.context
          ? {
            ...n.context,
            values: R.map((o) => o.id || o.value || o, n.context.values),
          }
          : null,
        containerId: n.type === 'PROMOTE' && promoteToContainer && container?.id ? container.id : null,
      }),
      actions,
    );

    if (selectAll) {
      commitMutation({
        mutation: toolBarQueryTaskAddMutation,
        variables: {
          input: {
            filters: jsonFilters,
            search,
            actions: finalActions,
            excluded_ids: Object.keys(deSelectedElements || {}),
            scope,
          },
        },
        onCompleted: () => {
          handleClearSelectedElements();
          MESSAGING$.notifySuccess(
            <span>
              {t(
                'The background task has been executed. You can monitor it on',
              )}{' '}
              <Link to="/dashboard/data/processing/tasks">
                {t('the dedicated page')}
              </Link>
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
            ids: mergingElement
              ? [mergingElement.id]
              : Object.keys(selectedElements),
            actions: finalActions,
            scope,
          },
        },
        onCompleted: () => {
          handleClearSelectedElements();
          MESSAGING$.notifySuccess(
            <span>
              {t(
                'The background task has been executed. You can monitor it on',
              )}{' '}
              <Link to="/dashboard/data/processing/tasks">
                {t('the dedicated page')}
              </Link>
              .
            </span>,
          );
          this.setState({ processing: false });
          this.handleCloseTask();
        },
      });
    }
  }

  renderFieldOptions(i, typesHaveScore) {
    const { t } = this.props;
    const { actionsInputs } = this.state;
    const disabled = R.isNil(actionsInputs[i]?.type) || R.isEmpty(actionsInputs[i]?.type);
    let options = [];
    if (actionsInputs[i]?.type === 'ADD') {
      options = [
        { label: t('Marking definitions'), value: 'object-marking' },
        { label: t('Labels'), value: 'object-label' },
        { label: t('External references'), value: 'external-reference' },
        { label: t('In containers'), value: 'container-object' },
      ];
    } else if (actionsInputs[i]?.type === 'REPLACE') {
      options = [
        { label: t('Marking definitions'), value: 'object-marking' },
        { label: t('Labels'), value: 'object-label' },
        { label: t('Author'), value: 'created-by' },
        { label: t('Confidence'), value: 'confidence' },
        { label: t('Description'), value: 'description' },
      ];
      if (typesHaveScore) {
        options.push({ label: t('Score'), value: 'x_opencti_score' });
      }
      if (this.props.type) {
        options.push({ label: t('Status'), value: 'x_opencti_workflow_id' });
      }
    } else if (actionsInputs[i]?.type === 'REMOVE') {
      options = [
        { label: t('Marking definitions'), value: 'object-marking' },
        { label: t('Labels'), value: 'object-label' },
        { label: t('External references'), value: 'external-reference' },
      ];
    }
    return (
      <Select
        variant="standard"
        disabled={disabled}
        value={actionsInputs[i]?.type}
        onChange={this.handleChangeActionInput.bind(this, i, 'field')}
      >
        {options.length > 0 ? (
          R.map(
            (n) => (
              <MenuItem key={n.value} value={n.value}>
                {n.label}
              </MenuItem>
            ),
            options,
          )
        ) : (
          <MenuItem value="none">{t('None')}</MenuItem>
        )}
      </Select>
    );
  }

  searchContainers(i, event, newValue) {
    if (!event) return;
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

  searchOrganizations(event, newValue) {
    if (!event) return;
    this.setState({ organizationInput: newValue && newValue.length > 0 ? newValue : '' });
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

  searchMarkingDefinitions(i, event, newValue) {
    if (!event) return;
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

  searchLabels(i, event, newValue) {
    if (!event) return;
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

  searchExternalReferences(i, event, newValue) {
    if (!event) return;
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

  searchIdentities(i, event, newValue) {
    if (!event) return;
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

  searchStatuses(i, event, newValue) {
    if (!event) return;
    const { actionsInputs } = this.state;
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
        filters: [{ key: 'type', values: [this.props.type] }],
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

  renderValuesOptions(i) {
    const { t, classes } = this.props;
    const { actionsInputs } = this.state;
    const disabled = R.isNil(actionsInputs[i]?.field) || R.isEmpty(actionsInputs[i]?.field);
    switch (actionsInputs[i]?.field) {
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
                this.handleChangeActionInputValues(i, null, [
                  ...(actionsInputs[i]?.values ?? []),
                  element,
                ]);
              }}
            />
            <Autocomplete
              disabled={disabled}
              size="small"
              fullWidth={true}
              selectOnFocus={true}
              autoHighlight={true}
              getOptionLabel={(option) => option.label ?? ''}
              value={actionsInputs[i]?.values || []}
              multiple={true}
              renderInput={(params) => (
                <TextField
                  {...params}
                  variant="standard"
                  label={t('Values')}
                  fullWidth={true}
                  onFocus={this.searchContainers.bind(this, i)}
                  style={{ marginTop: 3 }}
                />
              )}
              noOptionsText={t('No available options')}
              options={this.state.containers}
              onInputChange={this.searchContainers.bind(this, i)}
              inputValue={actionsInputs[i]?.inputValue || ''}
              onChange={this.handleChangeActionInputValues.bind(this, i)}
              renderOption={(props, option) => (
                <li {...props}>
                  <div className={classes.icon}>
                    <ItemIcon type={option.type} />
                  </div>
                  <div className={classes.text}>{option.label}</div>
                </li>
              )}
            />
            <IconButton
              onClick={() => this.setState({ containerCreation: true })}
              edge="end"
              style={{ position: 'absolute', top: 22, right: 48 }}
              size="large"
            >
              <AddOutlined />
            </IconButton>
          </>
        );
      case 'object-marking':
        return (
          <Autocomplete
            disabled={disabled}
            size="small"
            fullWidth={true}
            selectOnFocus={true}
            autoHighlight={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            multiple={true}
            renderInput={(params) => (
              <TextField
                {...params}
                variant="standard"
                label={t('Values')}
                fullWidth={true}
                onFocus={this.searchMarkingDefinitions.bind(this, i)}
                style={{ marginTop: 3 }}
              />
            )}
            noOptionsText={t('No available options')}
            options={this.state.markingDefinitions}
            onInputChange={this.searchMarkingDefinitions.bind(this, i)}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onChange={this.handleChangeActionInputValues.bind(this, i)}
            renderOption={(props, option) => (
              <li {...props}>
                <div className={classes.icon} style={{ color: option.color }}>
                  <CenterFocusStrong />
                </div>
                <div className={classes.text}>{option.label}</div>
              </li>
            )}
          />
        );
      case 'object-label':
        return (
          <Autocomplete
            disabled={disabled}
            size="small"
            fullWidth={true}
            selectOnFocus={true}
            autoHighlight={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            multiple={true}
            renderInput={(params) => (
              <TextField
                {...params}
                variant="standard"
                label={t('Values')}
                fullWidth={true}
                onFocus={this.searchLabels.bind(this, i)}
                style={{ marginTop: 3 }}
              />
            )}
            noOptionsText={t('No available options')}
            options={this.state.labels}
            onInputChange={this.searchLabels.bind(this, i)}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onChange={this.handleChangeActionInputValues.bind(this, i)}
            renderOption={(props, option) => (
              <li {...props}>
                <div className={classes.icon} style={{ color: option.color }}>
                  <LabelOutline />
                </div>
                <div className={classes.text}>{option.label}</div>
              </li>
            )}
          />
        );
      case 'created-by':
        return (
          <Autocomplete
            disabled={disabled}
            size="small"
            fullWidth={true}
            selectOnFocus={true}
            autoHighlight={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            renderInput={(params) => (
              <TextField
                {...params}
                variant="standard"
                label={t('Values')}
                fullWidth={true}
                onFocus={this.searchIdentities.bind(this, i)}
                style={{ marginTop: 3 }}
              />
            )}
            noOptionsText={t('No available options')}
            options={this.state.identities}
            onInputChange={this.searchIdentities.bind(this, i)}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onChange={this.handleChangeActionInputValues.bind(this, i)}
            renderOption={(props, option) => (
              <li {...props}>
                <div className={classes.icon}>
                  <ItemIcon type={option.type} />
                </div>
                <div className={classes.text}>{option.label}</div>
              </li>
            )}
          />
        );
      case 'x_opencti_workflow_id':
        return (
          <Autocomplete
            disabled={disabled}
            size="small"
            fullWidth={true}
            selectOnFocus={true}
            autoHighlight={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            renderInput={(params) => (
              <TextField
                {...params}
                variant="standard"
                label={t('Values')}
                fullWidth={true}
                onFocus={this.searchStatuses.bind(this, i)}
                style={{ marginTop: 3 }}
              />
            )}
            noOptionsText={t('No available options')}
            options={this.state.statuses}
            onInputChange={this.searchStatuses.bind(this, i)}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onChange={this.handleChangeActionInputValues.bind(this, i)}
            renderOption={(props, option) => (
              <li {...props}>
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
              </li>
            )}
          />
        );
      case 'external-reference':
        return (
          <Autocomplete
            disabled={disabled}
            size="small"
            fullWidth={true}
            selectOnFocus={true}
            autoHighlight={true}
            getOptionLabel={(option) => (option.label ? option.label : '')}
            value={actionsInputs[i]?.values || []}
            multiple={true}
            renderInput={(params) => (
              <TextField
                {...params}
                variant="standard"
                label={t('Values')}
                fullWidth={true}
                onFocus={this.searchExternalReferences.bind(this, i)}
                style={{ marginTop: 3 }}
              />
            )}
            noOptionsText={t('No available options')}
            options={this.state.externalReferences}
            onInputChange={this.searchExternalReferences.bind(this, i)}
            inputValue={actionsInputs[i]?.inputValue || ''}
            onChange={this.handleChangeActionInputValues.bind(this, i)}
            renderOption={(props, option) => (
              <li {...props}>
                <div className={classes.icon} style={{ color: option.color }}>
                  <LanguageOutlined />
                </div>
                <div className={classes.text}>{option.label}</div>
              </li>
            )}
          />
        );
      case 'x_opencti_score':
      case 'confidence':
        return (
          <TextField
            variant="standard"
            disabled={disabled}
            label={t('Values')}
            fullWidth={true}
            type="number"
            onChange={this.handleChangeActionInputValuesReplace.bind(this, i)}
          />
        );
      default:
        return (
          <TextField
            variant="standard"
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

  getSelectedTypes() {
    const entityTypeFilterValues = findFilterFromKey(this.props.filters?.filters ?? [], 'entity_type', 'eq')?.values ?? [];
    const selectedElementsList = Object.values(this.props.selectedElements || {});

    const selectedTypes = R.uniq([...selectedElementsList.map((o) => o.entity_type), ...entityTypeFilterValues]
      .filter((entity_type) => entity_type !== undefined));
    return { entityTypeFilterValues, selectedElementsList, selectedTypes };
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
      deleteOperationEnabled,
      warning,
      warningMessage,
      taskScope,
    } = this.props;
    const { actions, keptEntityId, mergingElement, actionsInputs, promoteToContainer } = this.state;
    const { entityTypeFilterValues, selectedElementsList, selectedTypes } = this.getSelectedTypes();

    // Some filter types are high level, we do not want to check them as "Different"
    // We might need to add some other types here before refactoring the toolbar
    const typesAreDifferent = (selectedTypes.filter((type) => !['Stix-Domain-Object', 'stix-core-relationship'].includes(type))).length > 1;
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
    const isManualEnrichSelect = !selectAll && selectedTypes.length === 1;
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
    const typesHaveScore = selectedTypes.every((selectedType) => typesWithScore.includes(selectedType))
      && entityTypeFilterValues.every((filterType) => typesWithScore.includes(filterType));

    let deleteCapability = KNOWLEDGE_KNUPDATE_KNDELETE;
    if (taskScope === 'DASHBOARD') deleteCapability = EXPLORE_EXUPDATE_EXDELETE;
    if (taskScope === 'PUBLIC_DASHBOARD') deleteCapability = EXPLORE_EXUPDATE_PUBLISH;
    if (taskScope === 'INVESTIGATION') deleteCapability = INVESTIGATION_INUPDATE_INDELETE;

    return (
      <UserContext.Consumer>
        {({ schema, settings }) => {
          // region EE
          const isEnterpriseEdition = isNotEmptyField(settings.enterprise_edition);
          // endregion
          // region promote filters
          const stixCyberObservableTypes = schema.scos.map((sco) => sco.id).concat('Stix-Cyber-Observable');
          const promotionTypes = stixCyberObservableTypes.concat(['Indicator']);

          const isOnlyStixCyberObservablesTypes = entityTypeFilterValues.length > 0
            && entityTypeFilterValues.every((id) => stixCyberObservableTypes.includes(id));

          const promotionTypesFiltered = entityTypeFilterValues.length > 0
            && entityTypeFilterValues.every((id) => promotionTypes.includes(id));

          const isManualPromoteSelect = !selectAll
            && selectedTypes.length > 0
            && selectedTypes.every((type) => promotionTypes.includes(type));

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
              <Toolbar style={{ minHeight: 40, marginTop: 2, display: 'flex', justifyContent: 'space-between', height: '100%' }} data-testid='opencti-toolbar'>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <Typography
                    className={classes.title}
                    color="inherit"
                    variant="subtitle1"
                  >
                    <span
                      style={{
                        padding: '2px 5px 2px 5px',
                        marginRight: 5,
                        backgroundColor: theme.palette.secondary.main,
                        color: theme.palette.secondary.contrastText,
                      }}
                    >
                      {numberOfSelectedElements}
                    </span>{' '}
                    {t('selected')}{' '}
                  </Typography>
                  <IconButton
                    aria-label="clear"
                    disabled={
                      numberOfSelectedElements === 0 || this.state.processing
                    }
                    onClick={handleClearSelectedElements.bind(this)}
                    size="small"
                    color="primary"
                  >
                    <ClearOutlined fontSize="small" />
                  </IconButton>
                </div>
                <div>
                  <Security needs={[KNOWLEDGE_KNUPDATE]}>
                    {!typesAreNotUpdatable && (
                      <Tooltip title={t('Update')}>
                        <span>
                          <IconButton
                            aria-label="update"
                            disabled={
                              numberOfSelectedElements === 0
                              || this.state.processing
                            }
                            onClick={this.handleOpenUpdate.bind(this)}
                            color="primary"
                            size="small"
                          >
                            <BrushOutlined fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    )}
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
                                color="primary"
                                size="small"
                              >
                                <AutoFixHighOutlined fontSize="small" />
                              </IconButton>
                            </span>
                          </Tooltip>
                        );
                      }}
                    </UserContext.Consumer>
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
                            color="primary"
                            size="small"
                          >
                            <ContentCopyOutlined fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    )}
                    {!enrichDisable && (
                      <Tooltip title={t('Enrichment')}>
                        <span>
                          <IconButton
                            aria-label="enrichment"
                            disabled={this.state.processing}
                            onClick={this.handleOpenEnrichment.bind(this)}
                            color="primary"
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
                            color="primary"
                            size="small"
                          >
                            <TransformOutlined fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    )}
                    {enableMerge && (
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
                            color="primary"
                            size="small"
                          >
                            <MergeOutlined fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    )}
                  </Security>
                  {!typesAreNotAddableInContainer && (
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
                            color="primary"
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
                            color="primary"
                            size="small"
                          >
                            <LinkOffOutlined fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    </Security>
                  )}
                  {!deleteOperationEnabled && isShareableType && (
                    <>
                      <Security needs={[KNOWLEDGE_KNUPDATE_KNORGARESTRICT]}>
                        <EETooltip title={t('Share with organizations')}>
                          <IconButton
                            color="primary"
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
                            color="primary"
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
                  {deleteDisable !== true && (
                    <Security needs={[deleteCapability]}>
                      <Tooltip title={warningMessage || t('Delete')}>
                        <span>
                          <IconButton
                            aria-label="delete"
                            disabled={
                              numberOfSelectedElements === 0
                              || this.state.processing
                            }
                            onClick={this.handleLaunchDelete.bind(this)}
                            color={warning ? 'warning' : 'primary'}
                            size="small"
                          >
                            <DeleteOutlined fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    </Security>
                  )}
                  {deleteOperationEnabled && (
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
                            color={warning ? 'warning' : 'primary'}
                            size="small"
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
                            color={warning ? 'warning' : 'primary'}
                            size="small"
                          >
                            <DeleteOutlined fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    </Security>
                  )}
                </div>
              </Toolbar>
              <Dialog
                PaperProps={{ elevation: 1 }}
                open={this.state.displayTask}
                keepMounted={true}
                TransitionComponent={Transition}
                onClose={this.handleCloseTask.bind(this)}
                fullWidth={true}
                maxWidth="md"
              >
                <DialogTitle>
                  <div style={{ float: 'left' }}>
                    {t('Launch a background task')}
                  </div>
                  <div style={{ float: 'right' }}>
                    <span
                      style={{
                        padding: '2px 5px 2px 5px',
                        marginRight: 5,
                        backgroundColor: theme.palette.secondary.main,
                        color: '#ffffff',
                      }}
                    >
                      {n(numberOfSelectedElements)}
                    </span>{' '}
                    {t('selected element(s)')}
                  </div>
                </DialogTitle>
                <DialogContent>
                  {numberOfSelectedElements > 1000 && (
                    <Alert severity="warning">
                      {t(
                        "You're targeting more than 1000 entities with this background task, be sure of what you're doing!",
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
                            <Chip style={{ borderRadius: 4 }} label="SCOPE" />
                          </TableCell>
                          <TableCell>{t('N/A')}</TableCell>
                          <TableCell>
                            {selectAll ? (
                              <div className={classes.filters}>
                                {search && search.length > 0 && (
                                  <span>
                                    <Chip
                                      classes={{ root: classes.filter }}
                                      label={
                                        <div>
                                          <strong>{t('Search')}</strong>: {search}
                                        </div>
                                      }
                                    />
                                    {filters.filters.length > 0 && (
                                      <Chip
                                        classes={{ root: classes.operator }}
                                        label={t('AND')}
                                      />
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
                                <Chip label={o.type} />
                              </TableCell>
                              <TableCell>
                                {R.pathOr(t('N/A'), ['context', 'field'], o)}
                              </TableCell>
                              <TableCell>
                                {truncate(
                                  R.join(
                                    ', ',
                                    R.map(
                                      (p) => (typeof p === 'string'
                                        ? p
                                        : getMainRepresentative(p)),
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
                </DialogContent>
                <DialogActions>
                  <Button
                    onClick={this.handleCloseTask.bind(this)}
                    disabled={this.state.processing}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    onClick={this.submitTask.bind(this, availableFilterKeys)}
                    color="secondary"
                    disabled={this.state.processing}
                  >
                    {t('Launch')}
                  </Button>
                </DialogActions>
              </Dialog>
              <Drawer
                open={this.state.displayUpdate}
                anchor="right"
                elevation={1}
                sx={{ zIndex: 1202 }}
                classes={{ paper: classes.drawerPaper }}
                onClose={this.handleCloseUpdate.bind(this)}
              >
                <div className={classes.header}>
                  <IconButton
                    aria-label="Close"
                    className={classes.closeButton}
                    onClick={this.handleCloseUpdate.bind(this)}
                    size="large"
                    color="primary"
                  >
                    <CloseOutlined fontSize="small" color="primary" />
                  </IconButton>
                  <Typography variant="h6">{t('Update entities')}</Typography>
                </div>
                <div className={classes.container} style={{ marginTop: 20 }}>
                  {Array(actionsInputs.length)
                    .fill(0)
                    .map((_, i) => (
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
                              <InputLabel>{t('Action type')}</InputLabel>
                              <Select
                                variant="standard"
                                value={actionsInputs[i]?.type}
                                onChange={this.handleChangeActionInput.bind(
                                  this,
                                  i,
                                  'type',
                                )}
                              >
                                <MenuItem value="ADD">{t('Add')}</MenuItem>
                                <MenuItem value="REPLACE">
                                  {t('Replace')}
                                </MenuItem>
                                <MenuItem value="REMOVE">{t('Remove')}</MenuItem>
                              </Select>
                            </FormControl>
                          </Grid>
                          <Grid item xs={3}>
                            <FormControl className={classes.formControl}>
                              <InputLabel>{t('Field')}</InputLabel>
                              {this.renderFieldOptions(i, typesHaveScore)}
                            </FormControl>
                          </Grid>
                          <Grid item xs={6}>
                            {this.renderValuesOptions(i)}
                          </Grid>
                        </Grid>
                      </div>
                    ))}
                  <div className={classes.add}>
                    <Button
                      disabled={!this.areStepValid()}
                      variant="contained"
                      color="secondary"
                      size="small"
                      onClick={this.handleAddStep.bind(this)}
                      classes={{ root: classes.buttonAdd }}
                    >
                      <AddOutlined fontSize="small" />
                    </Button>
                  </div>
                  <div className={classes.buttons}>
                    <Button
                      disabled={!this.areStepValid()}
                      variant="contained"
                      color="primary"
                      onClick={this.handleLaunchUpdate.bind(this)}
                      classes={{ root: classes.button }}
                    >
                      {t('Update')}
                    </Button>
                  </div>
                </div>
              </Drawer>
              <Drawer
                open={this.state.displayMerge}
                anchor="right"
                elevation={1}
                sx={{ zIndex: 1202 }}
                classes={{ paper: classes.drawerPaper }}
                onClose={this.handleCloseMerge.bind(this)}
              >
                <div className={classes.header}>
                  <IconButton
                    aria-label="Close"
                    className={classes.closeButton}
                    onClick={this.handleCloseMerge.bind(this)}
                    size="large"
                    color="primary"
                  >
                    <CloseOutlined fontSize="small" color="primary" />
                  </IconButton>
                  <Typography variant="h6">{t('Merge entities')}</Typography>
                </div>
                <div className={classes.container}>
                  <Typography
                    variant="h4"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Selected entities')}
                  </Typography>
                  <List>
                    {selectedElementsList.map((element) => (
                      <ListItem key={element.id} dense={true} divider={true}>
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
                          {R.pathOr('', ['createdBy', 'name'], element)}
                        </div>
                        <div style={{ marginRight: 50 }}>
                          <ItemMarkings
                            variant="inList"
                            markingDefinitions={
                              element.objectMarking ?? []
                            }
                          />
                        </div>
                        <ListItemSecondaryAction>
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
                        </ListItemSecondaryAction>
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
                    <Chip
                      key={label}
                      classes={{ root: classes.aliases }}
                      label={label}
                    />
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
                      {R.pathOr('', ['createdBy', 'name'], keptElement)}
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
                        markingDefinitions={
                          keptElement?.objectMarking || []
                        }
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
                  <div className={classes.buttons}>
                    <Button
                      variant="contained"
                      color="secondary"
                      onClick={this.handleLaunchMerge.bind(this)}
                      classes={{ root: classes.button }}
                    >
                      {t('Merge')}
                    </Button>
                  </div>
                </div>
              </Drawer>
              <Drawer
                open={this.state.displayEnrichment}
                anchor="right"
                elevation={1}
                sx={{ zIndex: 1202 }}
                classes={{ paper: classes.drawerPaper }}
                onClose={this.handleCloseEnrichment.bind(this)}
              >
                <div className={classes.header}>
                  <IconButton
                    aria-label="Close"
                    className={classes.closeButton}
                    onClick={this.handleCloseEnrichment.bind(this)}
                    size="large"
                    color="primary"
                  >
                    <CloseOutlined fontSize="small" color="primary" />
                  </IconButton>
                  <Typography variant="h6">{t('Entity enrichment')}</Typography>
                </div>
                <div className={classes.container}>
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
                      <ListItem key={connector.id} dense={true} divider={true}>
                        <ListItemIcon>
                          <CloudRefreshOutline />
                        </ListItemIcon>
                        <ListItemText primary={connector.name} />
                        <ListItemSecondaryAction>
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
                        </ListItemSecondaryAction>
                      </ListItem>
                    ))}
                  </List>
                  <div className={classes.buttons}>
                    <Button
                      variant="contained"
                      disabled={
                        this.state.enrichConnectors.length === 0
                        || this.state.enrichSelected.length === 0
                      }
                      color="secondary"
                      onClick={this.handleLaunchEnrichment.bind(this)}
                      classes={{ root: classes.button }}
                    >
                      {t('Enrich')}
                    </Button>
                  </div>
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
                open={this.state.displayRescan}
                anchor="right"
                elevation={1}
                sx={{ zIndex: 1202 }}
                classes={{ paper: classes.drawerPaper }}
                onClose={this.handleCloseRescan.bind(this)}
              >
                <div className={classes.header}>
                  <IconButton
                    aria-label="Close"
                    className={classes.closeButton}
                    onClick={this.handleCloseRescan.bind(this)}
                    size="large"
                    color="primary"
                  >
                    <CloseOutlined fontSize="small" color="primary" />
                  </IconButton>
                  <Typography variant="h6">{t('Rule entity rescan')}</Typography>
                </div>
                <div className={classes.container}>
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
                  <div className={classes.buttons}>
                    <Button
                      variant="contained"
                      color="secondary"
                      onClick={this.handleLaunchRescan.bind(this)}
                      classes={{ root: classes.button }}
                    >
                      {t('Rescan')}
                    </Button>
                  </div>
                </div>
              </Drawer>
              <Dialog
                PaperProps={{ elevation: 1 }}
                fullWidth={true}
                maxWidth="sm"
                TransitionComponent={Transition}
                open={this.state.displayAddInContainer}
                onClose={() => this.setState({ displayAddInContainer: false })}
              >
                <DialogTitle>{t('Add in container')}</DialogTitle>
                <DialogContent>
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
                  <Autocomplete
                    size="small"
                    fullWidth={true}
                    selectOnFocus={true}
                    autoHighlight={true}
                    getOptionLabel={(option) => (option.label ? option.label : '')}
                    value={actionsInputs[0]?.values || []}
                    multiple={true}
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        variant="standard"
                        label={t('Values')}
                        fullWidth={true}
                        onFocus={this.searchContainers.bind(this, 0)}
                        style={{ marginTop: 3 }}
                      />
                    )}
                    noOptionsText={t('No available options')}
                    options={this.state.containers}
                    onInputChange={this.searchContainers.bind(this, 0)}
                    inputValue={actionsInputs[0]?.inputValue || ''}
                    onChange={this.handleChangeActionInputValues.bind(this, 0)}
                    renderOption={(props, option) => (
                      <li {...props}>
                        <div className={classes.icon}>
                          <ItemIcon type={option.type} />
                        </div>
                        <div className={classes.text}>{option.label}</div>
                      </li>
                    )}
                    disableClearable
                  />
                  <FormControlLabel
                    style={{ marginTop: 20 }}
                    control={
                      <Checkbox
                        checked={
                          actionsInputs[0]?.options?.includeNeighbours || false
                        }
                        onChange={this.handleChangeActionInputOptions.bind(
                          this,
                          0,
                          'includeNeighbours',
                        )}
                      />
                    }
                    label={t('Also include first neighbours')}
                  />
                  <IconButton
                    onClick={() => this.setState({ containerCreation: true })}
                    edge="end"
                    style={{ position: 'absolute', top: 68, right: 48 }}
                    size="large"
                  >
                    <AddOutlined />
                  </IconButton>
                </DialogContent>
                <DialogActions>
                  <Button
                    onClick={() => this.setState({ displayAddInContainer: false })
                    }
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
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
                PaperProps={{ elevation: 1 }}
                fullWidth={true}
                maxWidth="sm"
                TransitionComponent={Transition}
                open={this.state.displayShare}
                onClose={() => this.setState({ displayShare: false })}
              >
                <DialogTitle>{t('Share with organizations')}</DialogTitle>
                <DialogContent>
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
                  <Autocomplete
                    size="small"
                    fullWidth={true}
                    selectOnFocus={true}
                    autoHighlight={true}
                    getOptionLabel={(option) => (option.label ? option.label : '')}
                    value={this.state.shareOrganizations}
                    multiple={true}
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        variant="standard"
                        label={t('Values')}
                        fullWidth={true}
                        onFocus={this.searchOrganizations.bind(this)}
                        style={{ marginTop: 3 }}
                      />
                    )}
                    noOptionsText={t('No available options')}
                    options={this.state.organizations}
                    onInputChange={this.searchOrganizations.bind(this)}
                    inputValue={this.state.organizationInput}
                    onChange={(_, value) => this.setState({ shareOrganizations: value })}
                    renderOption={(props, option) => (
                      <li {...props}>
                        <div className={classes.icon}>
                          <ItemIcon type={option.type} />
                        </div>
                        <div className={classes.text}>{option.label}</div>
                      </li>
                    )}
                    disableClearable
                  />
                  <IconButton
                    onClick={() => this.setState({ organizationCreation: true })}
                    edge="end"
                    style={{ position: 'absolute', top: 68, right: 48 }}
                    size="large"
                  >
                    <AddOutlined />
                  </IconButton>
                </DialogContent>
                <DialogActions>
                  <Button onClick={this.handleCloseShare.bind(this)}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={() => {
                      const shareActions = [
                        { type: 'SHARE_MULTIPLE', context: { values: this.state.shareOrganizations } },
                      ];
                      this.setState({ actions: shareActions }, () => {
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
                PaperProps={{ elevation: 1 }}
                fullWidth={true}
                maxWidth="sm"
                TransitionComponent={Transition}
                open={this.state.displayUnshare}
                onClose={() => this.setState({ displayUnshare: false })}
              >
                <DialogTitle>{t('Unshare with organizations')}</DialogTitle>
                <DialogContent>
                  <Autocomplete
                    size="small"
                    fullWidth={true}
                    selectOnFocus={true}
                    autoHighlight={true}
                    getOptionLabel={(option) => (option.label ? option.label : '')}
                    value={this.state.shareOrganizations}
                    multiple={true}
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        variant="standard"
                        label={t('Values')}
                        fullWidth={true}
                        onFocus={this.searchOrganizations.bind(this)}
                        style={{ marginTop: 3 }}
                      />
                    )}
                    noOptionsText={t('No available options')}
                    options={this.state.organizations}
                    onInputChange={this.searchOrganizations.bind(this)}
                    inputValue={this.state.organizationInput}
                    onChange={(_, value) => this.setState({ shareOrganizations: value })}
                    renderOption={(props, option) => (
                      <li {...props}>
                        <div className={classes.icon}>
                          <ItemIcon type={option.type} />
                        </div>
                        <div className={classes.text}>{option.label}</div>
                      </li>
                    )}
                    disableClearable
                  />
                </DialogContent>
                <DialogActions>
                  <Button onClick={this.handleCloseUnshare.bind(this)}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={() => {
                      const shareActions = [
                        { type: 'UNSHARE_MULTIPLE', context: { values: this.state.shareOrganizations } },
                      ];
                      this.setState({ actions: shareActions }, () => {
                        this.handleCloseUnshare();
                        this.handleOpenTask();
                      });
                    }}
                  >
                    {t('Unshare')}
                  </Button>
                </DialogActions>
              </Dialog>
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
  deleteOperationEnabled: PropTypes.bool,
  taskScope: PropTypes.string,
};

export default R.compose(inject18n, withTheme, withStyles(styles))(DataTableToolBar);
