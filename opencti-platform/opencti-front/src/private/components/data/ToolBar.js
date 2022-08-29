import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { ascend, map, path, pathOr, pipe, sortWith, union } from 'ramda';
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
  BrushOutlined,
  CancelOutlined,
  CenterFocusStrong,
  ClearOutlined,
  CloseOutlined,
  DeleteOutlined,
  LanguageOutlined,
  LinkOffOutlined,
  TransformOutlined,
} from '@mui/icons-material';
import { AutoFix, CloudRefresh, Label, Merge } from 'mdi-material-ui';
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
import { commitMutation, fetchQuery, MESSAGING$ } from '../../../relay/environment';
import ItemMarking from '../../../components/ItemMarking';
import ItemIcon from '../../../components/ItemIcon';
import { objectMarkingFieldAllowedMarkingsQuery } from '../common/form/ObjectMarkingField';
import { defaultValue } from '../../../utils/Graph';
import { identitySearchIdentitiesSearchQuery } from '../common/identities/IdentitySearch';
import { labelsSearchQuery } from '../settings/LabelsQuery';
import Security, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE, UserContext } from '../../../utils/Security';
import { statusFieldStatusesSearchQuery } from '../common/form/StatusField';
import { hexToRGB } from '../../../utils/Colors';
import { externalReferencesSearchQuery } from '../analysis/ExternalReferences';

const styles = (theme) => ({
  bottomNav: {
    zIndex: 1100,
    padding: '0 0 0 180px',
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  bottomNavWithPadding: {
    zIndex: 1100,
    padding: '0 230px 0 180px',
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  withSmallPaddingRight: {
    zIndex: 1100,
    padding: '0 200px 0 180px',
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

const notMergableTypes = ['Indicator', 'Note', 'Opinion'];

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const toolBarListTaskAddMutation = graphql`
  mutation ToolBarListTaskAddMutation($input: ListTaskAddInput) {
    listTaskAdd(input: $input) {
      id
      type
    }
  }
`;

const toolBarQueryTaskAddMutation = graphql`
  mutation ToolBarQueryTaskAddMutation($input: QueryTaskAddInput) {
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

class ToolBar extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayTask: false,
      displayUpdate: false,
      displayEnrichment: false,
      displayRescan: false,
      displayMerge: false,
      displayPromote: false,
      actions: [],
      actionsInputs: [{}],
      keptEntityId: null,
      mergingElement: null,
      processing: false,
      markingDefinitions: [],
      labels: [],
      identities: [],
      statuses: [],
      externalReferences: [],
      enrichConnectors: [],
      enrichSelected: [],
    };
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
      const selectedTypes = R.uniq(R.map((o) => o.entity_type, R.values(selected || {})));
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
        context: {
          type: 'REVERSED_RELATION',
          field: 'object',
          values: [this.props.container],
        },
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
      const filtered = this.state.enrichSelected.filter((e) => e !== connectorId);
      this.setState({ enrichSelected: filtered });
    } else {
      this.setState({ enrichSelected: [...this.state.enrichSelected, connectorId] });
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
    const actions = [{ type: 'ENRICHMENT', context: { values: this.state.enrichSelected } }];
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
        {
          label: t('Labels'),
          value: 'object-label',
        },
        {
          label: t('External references'),
          value: 'external-reference',
        },
      ];
    } else if (actionsInputs[i]?.type === 'REPLACE') {
      options = [
        { label: t('Marking definitions'), value: 'object-marking' },
        {
          label: t('Labels'),
          value: 'object-label',
        },
        {
          label: t('Author'),
          value: 'created-by',
        },
        {
          label: t('Score'),
          value: 'x_opencti_score',
        },
        {
          label: t('Confidence'),
          value: 'confidence',
        },
      ];
      if (this.props.type) {
        options.push({
          label: t('Status'),
          value: 'x_opencti_workflow_id',
        });
      }
    } else if (actionsInputs[i]?.type === 'REMOVE') {
      options = [
        { label: t('Marking definitions'), value: 'object-marking' },
        {
          label: t('Labels'),
          value: 'object-label',
        },
        {
          label: t('External references'),
          value: 'external-reference',
        },
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
        const labels = pipe(
          pathOr([], ['labels', 'edges']),
          map((n) => ({
            label: n.node.value,
            value: n.node.id,
            color: n.node.color,
          })),
        )(data);
        this.setState({
          labels: union(this.state.labels, labels),
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
    fetchQuery(externalReferencesSearchQuery, {
      search: newValue && newValue.length > 0 ? newValue : '',
    })
      .toPromise()
      .then((data) => {
        const externalReferences = pipe(
          pathOr([], ['externalReferences', 'edges']),
          sortWith([ascend(path(['node', 'source_name']))]),
          map((n) => ({
            label: `[${n.node.source_name}] ${truncate(
              n.node.description || n.node.external_id,
              150,
            )} ${n.node.url && `(${n.node.url})`}`,
            value: n.node.id,
          })),
        )(data);
        this.setState({
          externalReferences: union(
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
        const identities = pipe(
          pathOr([], ['identities', 'edges']),
          map((n) => ({
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
          })),
        )(data);
        this.setState({ identities: union(this.state.identities, identities) });
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
        const statuses = pipe(
          pathOr([], ['statuses', 'edges']),
          map((n) => ({
            label: this.props.t(`status_${n.node.template.name}`),
            value: n.node.id,
            order: n.node.order,
            color: n.node.template.color,
          })),
        )(data);
        this.setState({ statuses: union(this.state.statuses, statuses) });
      });
  }

  renderValuesOptions(i) {
    const { t, classes } = this.props;
    const { actionsInputs } = this.state;
    const disabled = R.isNil(actionsInputs[i]?.field) || R.isEmpty(actionsInputs[i]?.field);
    switch (actionsInputs[i]?.field) {
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
      withPaddingRight,
      withSmallPaddingRight,
      theme,
      container,
    } = this.props;
    const { actions, keptEntityId, mergingElement, actionsInputs } = this.state;
    const isOpen = numberOfSelectedElements > 0;
    const selectedTypes = R.uniq(R.map((o) => o.entity_type, R.values(selectedElements || {})));
    const typesAreDifferent = selectedTypes.length > 1;
    // region promote filters
    const promotionTypes = ['Stix-Cyber-Observable', 'Indicator'];
    const observablesFiltered = (filters?.entity_type ?? []).length === 1
        && R.head(filters.entity_type).id === 'Stix-Cyber-Observable';
    const isManualPromoteSelect = observablesFiltered || (!selectAll && selectedTypes.length === 1
        && promotionTypes.includes(R.head(selectedTypes)));
    const isAllPromoteSelect = selectAll && (filters?.entity_type ?? []).length === 1
        && promotionTypes.includes(R.head(filters.entity_type).id);
    const promoteDisable = !isManualPromoteSelect && !isAllPromoteSelect;
    // endregion
    // region enrich
    const isManualEnrichSelect = !selectAll && selectedTypes.length === 1;
    const isAllEnrichSelect = selectAll && (filters?.entity_type ?? []).length === 1;
    const enrichDisable = !isManualEnrichSelect && !isAllEnrichSelect;
    // endregion
    const typesAreNotMergable = R.includes(
      R.uniq(R.map((o) => o.entity_type, R.values(selectedElements || {})))[0],
      notMergableTypes,
    );
    const selectedElementsList = R.values(selectedElements || {});
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
    return (
      <Drawer
        anchor="bottom"
        variant="persistent"
        classes={{
          // eslint-disable-next-line no-nested-ternary
          paper: withPaddingRight
            ? classes.bottomNavWithPadding
            : withSmallPaddingRight
              ? classes.bottomNavWithSmallPadding
              : classes.bottomNav,
        }}
        open={isOpen}
        PaperProps={{ variant: 'elevation', elevation: 1 }}
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
              size="large"
            >
              <ClearOutlined fontSize="small" />
            </IconButton>
          </Typography>
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <Tooltip title={t('Update')}>
              <span>
                <IconButton
                  aria-label="update"
                  disabled={
                    numberOfSelectedElements === 0 || this.state.processing
                  }
                  onClick={this.handleOpenUpdate.bind(this)}
                  color="primary"
                  size="large"
                >
                  <BrushOutlined />
                </IconButton>
              </span>
            </Tooltip>
            <UserContext.Consumer>
              {({ helper }) => {
                const label = helper.isRuleEngineEnable()
                  ? 'Rule rescan'
                  : 'Rule rescan (engine is disabled)';
                const buttonDisable = !helper.isRuleEngineEnable()
                  || numberOfSelectedElements === 0
                  || this.state.processing;
                return (
                  <Tooltip title={t(label)}>
                    <span>
                      <IconButton
                        aria-label="update"
                        disabled={buttonDisable}
                        onClick={this.handleOpenRescan.bind(this)}
                        color="primary"
                        size="large"
                      >
                        <AutoFix />
                      </IconButton>
                    </span>
                  </Tooltip>
                );
              }}
            </UserContext.Consumer>
            <Tooltip title={t('Enrichment')}>
              <span>
                <IconButton
                    aria-label="enrichment"
                    disabled={ enrichDisable || this.state.processing }
                    onClick={this.handleOpenEnrichment.bind(this)}
                    color="primary"
                    size="large">
                  <CloudRefresh />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip title={t('Indicators/observables generation')}>
              <span>
                <IconButton
                    aria-label="promote"
                    disabled={ promoteDisable || this.state.processing }
                    onClick={this.handleOpenPromote.bind(this)}
                    color="primary"
                    size="large">
                  <TransformOutlined />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip title={t('Merge')}>
              <span>
                <IconButton
                  aria-label="merge"
                  disabled={
                    typesAreNotMergable
                    || typesAreDifferent
                    || numberOfSelectedElements < 2
                    || numberOfSelectedElements > 4
                    || selectAll
                    || this.state.processing
                  }
                  onClick={this.handleOpenMerge.bind(this)}
                  color="primary"
                  size="large"
                >
                  <Merge />
                </IconButton>
              </span>
            </Tooltip>
          </Security>
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
                    size="large"
                  >
                    <LinkOffOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            </Security>
          )}
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <Tooltip title={t('Delete')}>
              <span>
                <IconButton
                  aria-label="delete"
                  disabled={
                    numberOfSelectedElements === 0 || this.state.processing
                  }
                  onClick={this.handleLaunchDelete.bind(this)}
                  color="primary"
                  size="large"
                >
                  <DeleteOutlined />
                </IconButton>
              </span>
            </Tooltip>
          </Security>
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
                              <Chip
                                classes={{ root: classes.operator }}
                                label={t('AND')}
                              />
                            </span>
                          )}
                          {R.map((currentFilter) => {
                            const label = `${truncate(
                              t(`filter_${currentFilter[0]}`),
                              20,
                            )}`;
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
                                        !== o.value && <code>OR</code>}{' '}
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
                          }, R.toPairs(filters))}
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
                    size="large"
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
            <Typography variant="h4" gutterBottom={true} style={{ marginTop: 20 }}>
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
                    {R.pathOr([], ['objectMarking', 'edges'], element).length
                      > 0
                      && R.map(
                        (markingDefinition) => (
                          <ItemMarking
                            key={markingDefinition.node.id}
                            label={markingDefinition.node.definition}
                            color={markingDefinition.node.x_opencti_color}
                            variant="inList"
                          />
                        ),
                        element.objectMarking.edges,
                      )}
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
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Author')}
            </Typography>
            {R.pathOr('', ['createdBy', 'name'], keptElement)}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Marking')}
            </Typography>
            {R.pathOr([], ['markingDefinitions', 'edges'], keptElement).length
            > 0 ? (
                R.map(
                  (markingDefinition) => (
                  <ItemMarking
                    key={markingDefinition.node.id}
                    label={markingDefinition.node.definition}
                  />
                  ),
                  R.pathOr([], ['objectMarking', 'edges'], keptElement),
                )
              ) : (
              <ItemMarking label="TLP:CLEAR" />
              )}
            <Alert severity="warning" style={{ marginTop: 20 }}>
              {t(
                'The relations attached to selected entities will be copied to the merged entity.',
              )}
            </Alert>
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
        <Drawer open={this.state.displayEnrichment}
                anchor="right"
                elevation={1}
                sx={{ zIndex: 1202 }}
                classes={{ paper: classes.drawerPaper }}
                onClose={this.handleCloseEnrichment.bind(this)}>
          <div className={classes.header}>
            <IconButton aria-label="Close"
                        className={classes.closeButton}
                        onClick={this.handleCloseEnrichment.bind(this)}
                        size="large"
                        color="primary">
              <CloseOutlined fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Entity enrichment')}</Typography>
          </div>
          <div className={classes.container}>
            <Typography variant="h4" gutterBottom={true} style={{ marginTop: 20 }}>
              {t('Selected connectors')}
            </Typography>
            <List>
              {this.state.enrichConnectors.length === 0 && <Alert severity="warning">
                {t('No connector available for the selected entities.')}
              </Alert>}
              {this.state.enrichConnectors.map((connector) => (
                  <ListItem key={connector.id} dense={true} divider={true}>
                    <ListItemIcon>
                      <CloudRefresh />
                    </ListItemIcon>
                    <ListItemText primary={connector.name}/>
                    <ListItemSecondaryAction>
                      <MuiSwitch checked={this.state.enrichSelected.includes(connector.id)}
                          onChange={this.handleChangeEnrichSelected.bind(this, connector.id)}
                          inputProps={{ 'aria-label': 'controlled' }}
                      />
                    </ListItemSecondaryAction>
                  </ListItem>
              ))}
            </List>
            <div className={classes.buttons}>
              <Button variant="contained"
                      disabled={this.state.enrichConnectors.length === 0
                          || this.state.enrichSelected.length === 0}
                      color="secondary"
                      onClick={this.handleLaunchEnrichment.bind(this)}
                      classes={{ root: classes.button }}>
                {t('Enrich')}
              </Button>
            </div>
          </div>
        </Drawer>
        <Drawer open={this.state.displayPromote}
                anchor="right"
                elevation={1}
                sx={{ zIndex: 1202 }}
                classes={{ paper: classes.drawerPaper }}
                onClose={this.handleClosePromote.bind(this)}>
          <div className={classes.header}>
            <IconButton aria-label="Close"
                className={classes.closeButton}
                onClick={this.handleClosePromote.bind(this)}
                size="large"
                color="primary">
              <CloseOutlined fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Observables and indicators conversion')}</Typography>
          </div>
          <div className={classes.container}>
            { !observablesFiltered && <div>
              <Typography variant="h4" gutterBottom={true} style={{ marginTop: 20 }}>
                {t('Indicators')}
              </Typography>
              <Alert severity="warning" style={{ marginTop: 20 }}>
                {t('This action will generate observables from the selected indicators.')}
              </Alert>
            </div> }
            { observablesFiltered && <div>
              <Typography variant="h4" gutterBottom={true} style={{ marginTop: 20 }}>
                {t('Observables')}
              </Typography>
              <Alert severity="warning" style={{ marginTop: 20 }}>
                {t('This action will generate STIX patterns indicators from the selected observables.')}
              </Alert>
            </div> }
            <div className={classes.buttons}>
              <Button variant="contained"
                  color="secondary"
                  onClick={this.handleLaunchPromote.bind(this)}
                  classes={{ root: classes.button }}>
                {t('Generate')}
              </Button>
            </div>
          </div>
        </Drawer>
        <Drawer open={this.state.displayRescan}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseRescan.bind(this)}>
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
            <Typography variant="h4" gutterBottom={true} style={{ marginTop: 20 }}>
              {t('Selected rules')}
            </Typography>
            <Alert severity="warning" style={{ marginTop: 20 }}>
              {t('Element will be rescan with all compatible activated rules')}
            </Alert>
            <div className={classes.buttons}>
              <Button variant="contained" color="secondary" onClick={this.handleLaunchRescan.bind(this)} classes={{ root: classes.button }}>
                {t('Rescan')}
              </Button>
            </div>
          </div>
        </Drawer>
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
  withPaddingRight: PropTypes.bool,
  withSmallPaddingRight: PropTypes.bool,
  container: PropTypes.object,
  type: PropTypes.string,
};

export default R.compose(inject18n, withTheme, withStyles(styles))(ToolBar);
