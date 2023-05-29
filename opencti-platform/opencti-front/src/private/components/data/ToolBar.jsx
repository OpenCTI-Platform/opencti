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
  Add,
  AddOutlined,
  BrushOutlined,
  CancelOutlined,
  CenterFocusStrong,
  ClearOutlined,
  CloseOutlined,
  DeleteOutlined,
  LanguageOutlined,
  LinkOffOutlined,
  TransformOutlined,
  ContentCopyOutlined,
  AutoFixHighOutlined,
  MergeOutlined,
  Input,
} from '@mui/icons-material';
import { CloudRefresh, CloudRefreshOutline, Label } from 'mdi-material-ui';
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
import inject18n from '../../../components/i18n';
import { truncate } from '../../../utils/String';
import {
  commitMutation,
  fetchQuery,
  MESSAGING$,
} from '../../../relay/environment';
import ItemIcon from '../../../components/ItemIcon';
import { objectMarkingFieldAllowedMarkingsQuery } from '../common/form/ObjectMarkingField';
import { defaultValue } from '../../../utils/Graph';
import { identitySearchIdentitiesSearchQuery } from '../common/identities/IdentitySearch';
import { labelsSearchQuery } from '../settings/LabelsQuery';
import Security from '../../../utils/Security';
import {
  KNOWLEDGE_KNUPDATE,
  KNOWLEDGE_KNUPDATE_KNDELETE,
} from '../../../utils/hooks/useGranted';
import { UserContext } from '../../../utils/hooks/useAuth';
import { statusFieldStatusesSearchQuery } from '../common/form/StatusField';
import { hexToRGB } from '../../../utils/Colors';
import { externalReferencesQueriesSearchQuery } from '../analysis/external_references/ExternalReferencesQueries';
import StixDomainObjectCreation from '../common/stix_domain_objects/StixDomainObjectCreation';
import ItemMarkings from '../../../components/ItemMarkings';

const styles = (theme) => ({
  bottomNav: {
    padding: 0,
    zIndex: 1100,
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  bottomNavWithLargePadding: {
    zIndex: 1100,
    padding: '0 230px 0 0',
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  bottomNavWithMediumPadding: {
    zIndex: 1100,
    padding: '0 200px 0 0',
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  bottomNavWithSmallPadding: {
    zIndex: 1100,
    padding: '0 180px 0 0',
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
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

const notMergableTypes = ['Indicator', 'Note', 'Opinion', 'Label', 'Case-Template', 'Case-Task'];

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const toolBarListTaskAddMutation = graphql`
  mutation ToolBarListTaskAddMutation($input: ListTaskAddInput!) {
    listTaskAdd(input: $input) {
      id
      type
    }
  }
`;

const toolBarQueryTaskAddMutation = graphql`
  mutation ToolBarQueryTaskAddMutation($input: QueryTaskAddInput!) {
    queryTaskAdd(input: $input) {
      id
      type
    }
  }
`;

const toolBarConnectorsQuery = graphql`
  query ToolBarConnectorsQuery($type: String!) {
    enrichmentConnectors(type: $type) {
      id
      name
    }
  }
`;

export const maxNumberOfObservablesToCopy = 1000;

const toolBarContainersQuery = graphql`
  query ToolBarContainersQuery($search: String) {
    containers(
      search: $search
      filters: [{ key: entity_type, values: ["Container"] }]
    ) {
      edges {
        node {
          id
          entity_type
          representative
        }
      }
    }
  }
`;

class ToolBar extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayTask: false,
      displayUpdate: false,
      displayEnrichment: false,
      displayRescan: false,
      displayMerge: false,
      displayAddInContainer: false,
      displayPromote: false,
      containerCreation: false,
      actions: [],
      actionsInputs: [{}],
      keptEntityId: null,
      mergingElement: null,
      processing: false,
      markingDefinitions: [],
      labels: [],
      identities: [],
      containers: [],
      statuses: [],
      externalReferences: [],
      enrichConnectors: [],
      enrichSelected: [],
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
      enrichType = R.head(this.props.filters.entity_type).id;
    } else {
      const selected = this.props.selectedElements;
      const selectedTypes = R.uniq(
        R.map((o) => o.entity_type, R.values(selected || {})),
      );
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
      const values = value === 'creator_id' ? ['From history'] : [];
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

  submitTask() {
    this.setState({ processing: true });
    const { actions, mergingElement } = this.state;
    const {
      filters,
      search,
      selectAll,
      selectedElements,
      deSelectedElements,
      numberOfSelectedElements,
      handleClearSelectedElements,
      t,
    } = this.props;
    if (numberOfSelectedElements === 0) return;
    const jsonFilters = JSON.stringify(filters);
    const finalActions = R.map(
      (n) => ({
        type: n.type,
        context: n.context
          ? {
            ...n.context,
            values: R.map((o) => o.id || o.value || o, n.context.values),
          }
          : null,
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
          },
        },
        onCompleted: () => {
          handleClearSelectedElements();
          MESSAGING$.notifySuccess(
            <span>
              {t(
                'The background task has been executed. You can monitor it on',
              )}{' '}
              <Link to="/dashboard/data/tasks">{t('the dedicated page')}</Link>.
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
          },
        },
        onCompleted: () => {
          handleClearSelectedElements();
          MESSAGING$.notifySuccess(
            <span>
              {t(
                'The background task has been executed. You can monitor it on',
              )}{' '}
              <Link to="/dashboard/data/tasks">{t('the dedicated page')}</Link>.
            </span>,
          );
          this.setState({ processing: false });
          this.handleCloseTask();
        },
      });
    }
  }

  renderFieldOptions(i) {
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
        { label: t('Score'), value: 'x_opencti_score' },
        { label: t('Confidence'), value: 'confidence' },
        { label: t('filter_creator'), value: 'creator_id' },
      ];
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
        const containers = elements.map((n) => ({
          label: n.representative,
          type: n.entity_type,
          value: n.id,
        }));
        this.setState({ containers });
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
        const markingDefinitions = R.pipe(
          R.pathOr([], ['me', 'allowed_marking']),
          R.map((n) => ({
            label: n.definition,
            value: n.id,
            color: n.x_opencti_color,
          })),
        )(data);
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
        const labels = R.pipe(
          R.pathOr([], ['labels', 'edges']),
          R.map((n) => ({
            label: n.node.value,
            value: n.node.id,
            color: n.node.color,
          })),
        )(data);
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
        const externalReferences = R.pipe(
          R.pathOr([], ['externalReferences', 'edges']),
          R.sortWith([R.ascend(R.path(['node', 'source_name']))]),
          R.map((n) => ({
            label: `[${n.node.source_name}] ${truncate(
              n.node.description || n.node.external_id,
              150,
            )} ${n.node.url && `(${n.node.url})`}`,
            value: n.node.id,
          })),
        )(data);
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
      types: ['Individual', 'Organization'],
      search: newValue && newValue.length > 0 ? newValue : '',
      first: 10,
    })
      .toPromise()
      .then((data) => {
        const identities = R.pipe(
          R.pathOr([], ['identities', 'edges']),
          R.map((n) => ({
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
          })),
        )(data);
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
      first: 10,
      filters: [{ key: 'type', values: [this.props.type] }],
      orderBy: 'order',
      orderMode: 'asc',
      search: newValue && newValue.length > 0 ? newValue : '',
    })
      .toPromise()
      .then((data) => {
        const statuses = R.pipe(
          R.pathOr([], ['statuses', 'edges']),
          R.map((n) => ({
            label: n.node.template.name,
            value: n.node.id,
            order: n.node.order,
            color: n.node.template.color,
          })),
        )(data);
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
                this.handleChangeActionInputValues(i, null, [...(actionsInputs[i]?.values ?? []), element]);
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
              <Add />
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
                  <Label />
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
            value={actionsInputs[i]?.values ? actionsInputs[i]?.values[0] : ''}
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
      case 'confidence':
        return (
          <FormControl style={{ width: '100%' }}>
            <InputLabel variant="standard">{t('Values')}</InputLabel>
            <Select
              variant="standard"
              onChange={this.handleChangeActionInputValuesReplace.bind(this, i)}
              label={t('Values')}
              fullWidth={true}
            >
              <MenuItem value="0">{t('None')}</MenuItem>
              <MenuItem value="15">{t('Low')}</MenuItem>
              <MenuItem value="50">{t('Moderate')}</MenuItem>
              <MenuItem value="75">{t('Good')}</MenuItem>
              <MenuItem value="85">{t('Strong')}</MenuItem>
            </Select>
          </FormControl>
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
            value={actionsInputs[i]?.values ? actionsInputs[i]?.values[0] : ''}
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
      case 'creator_id':
        return (
          <TextField
            variant="standard"
            disabled={true}
            label="&nbsp;"
            fullWidth={true}
            value={'From history'}
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
      variant,
      noAuthor,
      noMarking,
      noWarning,
      deleteDisable,
      warning,
    } = this.props;
    const { actions, keptEntityId, mergingElement, actionsInputs, navOpen } = this.state;
    const isOpen = numberOfSelectedElements > 0;
    const selectedTypes = R.uniq(
      R.map((o) => o.entity_type, R.values(selectedElements || {})),
    );
    const typesAreDifferent = selectedTypes.length > 1;
    const preventMerge = selectedTypes.at(0) === 'Vocabulary'
      && Object.values(selectedElements).some(({ builtIn }) => Boolean(builtIn));
    // region update
    const notUpdatableTypes = ['Label', 'Vocabulary', 'Case-Template', 'Case-Task'];
    const typesAreNotUpdatable = R.includes(
      R.uniq(
        R.map((o) => o.entity_type, R.values(selectedElements || {})),
      )[0],
      notUpdatableTypes,
    )
      || ((filters?.entity_type ?? []).length === 1
        && notUpdatableTypes.includes(R.head(filters.entity_type).id));
    // endregion
    // region rules
    const notScannableTypes = ['Label', 'Vocabulary', 'Case-Template', 'Case-Task'];
    const typesAreNotScannable = R.includes(
      R.uniq(
        R.map((o) => o.entity_type, R.values(selectedElements || {})),
      )[0],
      notScannableTypes,
    )
      || ((filters?.entity_type ?? []).length === 1
        && notScannableTypes.includes(R.head(filters.entity_type).id));
    // endregion
    // region promote filters
    const promotionTypes = ['Stix-Cyber-Observable', 'Indicator'];
    const observablesFiltered = (filters?.entity_type ?? []).length === 1
      && R.head(filters.entity_type).id === 'Stix-Cyber-Observable';
    const isManualPromoteSelect = observablesFiltered
      || (!selectAll
        && selectedTypes.length === 1
        && promotionTypes.includes(R.head(selectedTypes)));
    const isAllPromoteSelect = selectAll
      && (filters?.entity_type ?? []).length === 1
      && promotionTypes.includes(R.head(filters.entity_type).id);
    const promoteDisable = !isManualPromoteSelect && !isAllPromoteSelect;
    // endregion
    // region enrich
    const notEnrichableTypes = ['Label', 'Vocabulary', 'Case-Template', 'Case-Task'];
    const isManualEnrichSelect = !selectAll && selectedTypes.length === 1;
    const isAllEnrichSelect = selectAll && (filters?.entity_type ?? []).length === 1;
    const enrichDisable = notEnrichableTypes.includes(R.head(selectedTypes))
      || ((filters?.entity_type ?? []).length === 1
        && notEnrichableTypes.includes(R.head(filters.entity_type).id))
      || (!isManualEnrichSelect && !isAllEnrichSelect);
    // endregion
    const typesAreNotMergable = R.includes(
      R.uniq(R.map((o) => o.entity_type, R.values(selectedElements || {})))[0],
      notMergableTypes,
    );
    const notAddableTypes = ['Label', 'Vocabulary', 'Case-Template'];
    const typesAreNotAddableInContainer = R.includes(
      R.uniq(R.map((o) => o.entity_type, R.values(selectedElements || {})))[0],
      notAddableTypes,
    );
    const selectedElementsList = R.values(selectedElements || {});
    const titleCopy = this.titleCopy();
    let keptElement = null;
    let newAliases = [];
    if (!typesAreNotMergable && !typesAreDifferent) {
      keptElement = keptEntityId
        ? R.head(R.filter((o) => o.id === keptEntityId, selectedElementsList))
        : R.head(selectedElementsList);
      if (keptElement) {
        const names = R.filter(
          (o) => o !== keptElement.name,
          R.pluck('name', selectedElementsList),
        );
        const aliases = !R.isNil(keptElement.aliases)
          ? R.filter(
            (o) => !R.isNil(o),
            R.flatten(R.pluck('aliases', selectedElementsList)),
          )
          : R.filter(
            (o) => !R.isNil(o),
            R.flatten(R.pluck('x_opencti_aliases', selectedElementsList)),
          );
        newAliases = R.filter(
          (o) => o.length > 0,
          R.uniq(R.concat(names, aliases)),
        );
      }
    }
    let paperClass;
    switch (variant) {
      case 'large':
        paperClass = classes.bottomNavWithLargePadding;
        break;
      case 'medium':
        paperClass = classes.bottomNavWithMediumPadding;
        break;
      case 'small':
        paperClass = classes.bottomNavWithSmallPadding;
        break;
      default:
        paperClass = classes.bottomNav;
    }
    return (
      <Drawer
        anchor="bottom"
        variant="persistent"
        classes={{ paper: paperClass }}
        open={isOpen}
        PaperProps={{
          variant: 'elevation',
          elevation: 1,
          style: { paddingLeft: navOpen ? 185 : 60 },
        }}
      >
        <Toolbar style={{ minHeight: 54 }}>
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
                color: '#ffffff',
              }}
            >
              {numberOfSelectedElements}
            </span>{' '}
            {t('selected')}{' '}
            <IconButton
              aria-label="clear"
              disabled={numberOfSelectedElements === 0 || this.state.processing}
              onClick={handleClearSelectedElements.bind(this)}
              size="small"
            >
              <ClearOutlined fontSize="small" />
            </IconButton>
          </Typography>
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            {!typesAreNotUpdatable && (
              <Tooltip title={t('Update')}>
                <span>
                  <IconButton
                    aria-label="update"
                    disabled={
                      numberOfSelectedElements === 0 || this.state.processing
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
                      numberOfSelectedElements > maxNumberOfObservablesToCopy
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
            {!promoteDisable && (
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
            {!typesAreNotMergable && (
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
                      numberOfSelectedElements === 0 || this.state.processing
                    }
                    onClick={this.handleOpenAddInContainer.bind(this)}
                    color="primary"
                    size="small"
                  >
                    <Input fontSize="small" />
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
                      numberOfSelectedElements === 0 || this.state.processing
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
          {deleteDisable !== true && (
            <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
              <Tooltip title={t('Delete')}>
                <span>
                  <IconButton
                    aria-label="delete"
                    disabled={
                      numberOfSelectedElements === 0 || this.state.processing
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
            <div style={{ float: 'left' }}>{t('Launch a background task')}</div>
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
                      <Chip label="SCOPE" />
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
                              {R.toPairs(filters).length > 0 && (
                                <Chip
                                  classes={{ root: classes.operator }}
                                  label={t('AND')}
                                />
                              )}
                            </span>
                          )}
                          {R.toPairs(filters).map((currentFilter) => {
                            const label = `${truncate(
                              currentFilter[0].startsWith('rel_')
                                ? t(
                                  `relationship_${currentFilter[0]
                                    .replace('rel_', '')
                                    .replace('.*', '')}`,
                                )
                                : t(`filter_${currentFilter[0]}`),
                              20,
                            )}`;
                            const localFilterMode = currentFilter[0].endsWith(
                              'not_eq',
                            )
                              ? t('AND')
                              : t('OR');
                            const values = (
                              <span>
                                {R.map(
                                  (o) => (
                                    <span
                                      key={typeof o === 'string' ? o : o.value}
                                    >
                                      {/* eslint-disable-next-line no-nested-ternary */}
                                      {typeof o === 'string'
                                        ? o
                                        : o.value && o.value.length > 0
                                          ? truncate(o.value, 15)
                                          : t('No label')}{' '}
                                      {R.last(currentFilter[1]).value
                                        !== o.value && (
                                        <code>{localFilterMode}</code>
                                      )}{' '}
                                    </span>
                                  ),
                                  currentFilter[1],
                                )}
                              </span>
                            );
                            return (
                              <span key={currentFilter[0]}>
                                <Chip
                                  classes={{ root: classes.filter }}
                                  label={
                                    <div>
                                      <strong>{label}</strong>: {values}
                                    </div>
                                  }
                                />
                                {R.last(R.toPairs(filters))[0]
                                  !== currentFilter[0] && (
                                  <Chip
                                    classes={{ root: classes.operator }}
                                    label={t('AND')}
                                  />
                                )}
                              </span>
                            );
                          })}
                        </div>
                      ) : (
                        <span>
                          {mergingElement
                            ? truncate(
                              R.join(', ', [defaultValue(mergingElement)]),
                              80,
                            )
                            : truncate(
                              R.join(
                                ', ',
                                R.map(
                                  (o) => defaultValue(o),
                                  R.values(selectedElements || {}),
                                ),
                              ),
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
                                (p) => (typeof p === 'string' ? p : defaultValue(p)),
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
              onClick={this.submitTask.bind(this)}
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
                    <Grid item={true} xs={3}>
                      <FormControl className={classes.formControl}>
                        <InputLabel variant="standard">
                          {t('Action type')}
                        </InputLabel>
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
                          <MenuItem value="REPLACE">{t('Replace')}</MenuItem>
                          <MenuItem value="REMOVE">{t('Remove')}</MenuItem>
                        </Select>
                      </FormControl>
                    </Grid>
                    <Grid item={true} xs={3}>
                      <FormControl className={classes.formControl}>
                        <InputLabel variant="standard">{t('Field')}</InputLabel>
                        {this.renderFieldOptions(i)}
                      </FormControl>
                    </Grid>
                    <Grid item={true} xs={6}>
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
                    primary={defaultValue(element)}
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
                      markingDefinitionsEdges={
                        element.objectMarking?.edges ?? []
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
            {defaultValue(keptElement)}
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
                  markingDefinitionsEdges={
                    keptElement?.markingDefinitions?.edges || []
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
                    <CloudRefresh />
                  </ListItemIcon>
                  <ListItemText primary={connector.name} />
                  <ListItemSecondaryAction>
                    <MuiSwitch
                      checked={this.state.enrichSelected.includes(connector.id)}
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
        <Drawer
          open={this.state.displayPromote}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClosePromote.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClosePromote.bind(this)}
              size="large"
              color="primary"
            >
              <CloseOutlined fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">
              {t('Observables and indicators conversion')}
            </Typography>
          </div>
          <div className={classes.container}>
            {!observablesFiltered && (
              <div>
                <Typography
                  variant="h4"
                  gutterBottom={true}
                  style={{ marginTop: 20 }}
                >
                  {t('Indicators')}
                </Typography>
                <Alert severity="warning" style={{ marginTop: 20 }}>
                  {t(
                    'This action will generate observables from the selected indicators.',
                  )}
                </Alert>
              </div>
            )}
            {observablesFiltered && (
              <div>
                <Typography
                  variant="h4"
                  gutterBottom={true}
                  style={{ marginTop: 20 }}
                >
                  {t('Observables')}
                </Typography>
                <Alert severity="warning" style={{ marginTop: 20 }}>
                  {t(
                    'This action will generate STIX patterns indicators from the selected observables.',
                  )}
                </Alert>
              </div>
            )}
            <div className={classes.buttons}>
              <Button
                variant="contained"
                color="secondary"
                onClick={this.handleLaunchPromote.bind(this)}
                classes={{ root: classes.button }}
              >
                {t('Generate')}
              </Button>
            </div>
          </div>
        </Drawer>
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
              {t('Element will be rescan with all compatible activated rules')}
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
                this.handleChangeActionInputValues(0, null, [...(actionsInputs[0]?.values ?? []), element]);
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
            <IconButton
              onClick={() => this.setState({ containerCreation: true })}
              edge="end"
              style={{ position: 'absolute', top: 68, right: 48 }}
              size="large"
            >
              <Add />
            </IconButton>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={() => this.setState({ displayAddInContainer: false })}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={() => {
                this.setState({
                  displayAddInContainer: false,
                  actionsInputs: [{
                    ...actionsInputs[0],
                    type: 'ADD',
                    fieldType: 'ATTRIBUTE',
                    field: 'container-object',
                  }],
                }, this.handleLaunchUpdate.bind(this));
              }}
            >
              {t('Add')}
            </Button>
          </DialogActions>
        </Dialog>
      </Drawer>
    );
  }
}

ToolBar.propTypes = {
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
};

export default R.compose(inject18n, withTheme, withStyles(styles))(ToolBar);
