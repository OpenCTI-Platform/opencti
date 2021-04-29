import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Toolbar from '@material-ui/core/Toolbar';
import Typography from '@material-ui/core/Typography';
import Tooltip from '@material-ui/core/Tooltip';
import List from '@material-ui/core/List';
import Radio from '@material-ui/core/Radio';
import FormControl from '@material-ui/core/FormControl';
import InputLabel from '@material-ui/core/InputLabel';
import MenuItem from '@material-ui/core/MenuItem';
import Select from '@material-ui/core/Select';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Table from '@material-ui/core/Table';
import TableHead from '@material-ui/core/TableHead';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import TableContainer from '@material-ui/core/TableContainer';
import TableRow from '@material-ui/core/TableRow';
import IconButton from '@material-ui/core/IconButton';
import {
  AddOutlined,
  DeleteOutlined,
  ClearOutlined,
  CloseOutlined,
  BrushOutlined,
  CenterFocusStrong,
  CancelOutlined,
} from '@material-ui/icons';
import { Label, Merge } from 'mdi-material-ui';
import Autocomplete from '@material-ui/lab/Autocomplete';
import Drawer from '@material-ui/core/Drawer';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import Chip from '@material-ui/core/Chip';
import DialogTitle from '@material-ui/core/DialogTitle';
import Alert from '@material-ui/lab/Alert';
import TextField from '@material-ui/core/TextField';
import Grid from '@material-ui/core/Grid';
import {
  map, pathOr, pipe, union,
} from 'ramda';
import inject18n from '../../../components/i18n';
import { truncate } from '../../../utils/String';
import {
  commitMutation,
  fetchQuery,
  MESSAGING$,
} from '../../../relay/environment';
import ThemeDark from '../../../components/ThemeDark';
import ItemMarking from '../../../components/ItemMarking';
import ItemIcon from '../../../components/ItemIcon';
import { objectMarkingFieldAllowedMarkingsQuery } from '../common/form/ObjectMarkingField';
import { defaultValue } from '../../../utils/Graph';
import { identityCreationIdentitiesSearchQuery } from '../common/identities/IdentityCreation';
import { labelsSearchQuery } from '../settings/LabelsQuery';

const styles = (theme) => ({
  bottomNav: {
    zIndex: 1100,
    padding: '0 0 0 180px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  bottomNavWithPadding: {
    zIndex: 1100,
    padding: '0 230px 0 180px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
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
    backgroundColor: 'rgba(64, 193, 255, 0.2)',
    margin: '5px 10px 5px 0',
  },
  step: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.background.paperLight}`,
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

class ToolBar extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayTask: false,
      displayUpdate: false,
      displayMerge: false,
      actions: [],
      actionsInputs: [{}],
      keptEntityId: null,
      mergingElement: null,
      processing: false,
      markingDefinitions: [],
      labels: [],
      identities: [],
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

  handleCloseUpdate() {
    this.setState({ displayUpdate: false, actionsInputs: [{}] });
  }

  handleOpenMerge() {
    this.setState({ displayMerge: true });
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

  handleChangeKeptEntityId(entityId) {
    this.setState({ keptEntityId: entityId });
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
      selectAll,
      selectedElements,
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
            values: R.map((o) => o.id || o.value, n.context.values),
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
      ];
    } else if (actionsInputs[i]?.type === 'REMOVE') {
      options = [
        { label: t('Marking definitions'), value: 'object-marking' },
        {
          label: t('Labels'),
          value: 'object-label',
        },
      ];
    }
    return (
      <Select
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

  searchIdentities(i, event, newValue) {
    if (!event) return;
    const { actionsInputs } = this.state;
    actionsInputs[i] = R.assoc(
      'inputValue',
      newValue && newValue.length > 0 ? newValue : '',
      actionsInputs[i],
    );
    this.setState({ actionsInputs });
    fetchQuery(identityCreationIdentitiesSearchQuery, {
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
            renderOption={(option) => (
              <React.Fragment>
                <div className={classes.icon} style={{ color: option.color }}>
                  <CenterFocusStrong />
                </div>
                <div className={classes.text}>{option.label}</div>
              </React.Fragment>
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
            renderOption={(option) => (
              <React.Fragment>
                <div className={classes.icon} style={{ color: option.color }}>
                  <Label />
                </div>
                <div className={classes.text}>{option.label}</div>
              </React.Fragment>
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
            renderOption={(option) => (
              <React.Fragment>
                <div className={classes.icon}>
                  <ItemIcon type={option.type} />
                </div>
                <div className={classes.text}>{option.label}</div>
              </React.Fragment>
            )}
          />
        );
      default:
        return (
          <TextField
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
      withPaddingRight,
    } = this.props;
    const {
      actions, keptEntityId, mergingElement, actionsInputs,
    } = this.state;
    const isOpen = numberOfSelectedElements > 0;
    const typesAreDifferent = R.uniq(R.map((o) => o.entity_type, R.values(selectedElements || {})))
      .length > 1;
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
          paper: withPaddingRight
            ? classes.bottomNavWithPadding
            : classes.bottomNav,
        }}
        open={isOpen}
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
                backgroundColor: ThemeDark.palette.secondary.main,
              }}
            >
              {numberOfSelectedElements}
            </span>{' '}
            {t('selected')}{' '}
            <IconButton
              aria-label="clear"
              disabled={numberOfSelectedElements === 0 || this.state.processing}
              onClick={handleClearSelectedElements.bind(this)}
            >
              <ClearOutlined fontSize="small" />
            </IconButton>
          </Typography>
          <Tooltip title={t('Update')}>
            <span>
              <IconButton
                aria-label="update"
                disabled={
                  numberOfSelectedElements === 0 || this.state.processing
                }
                onClick={this.handleOpenUpdate.bind(this)}
                color="primary"
              >
                <BrushOutlined />
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
              >
                <Merge />
              </IconButton>
            </span>
          </Tooltip>
          <Tooltip title={t('Delete')}>
            <span>
              <IconButton
                aria-label="delete"
                disabled={
                  numberOfSelectedElements === 0 || this.state.processing
                }
                onClick={this.handleLaunchDelete.bind(this)}
                color="primary"
              >
                <DeleteOutlined />
              </IconButton>
            </span>
          </Tooltip>
        </Toolbar>
        <Dialog
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
                  backgroundColor: ThemeDark.palette.secondary.main,
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
                          color: '#000000',
                          backgroundColor: ThemeDark.palette.primary.main,
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
                              color: '#000000',
                              backgroundColor: ThemeDark.palette.primary.main,
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
              color="primary"
              disabled={this.state.processing}
            >
              {t('Launch')}
            </Button>
          </DialogActions>
        </Dialog>
        <Drawer
          open={this.state.displayUpdate}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseUpdate.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleCloseUpdate.bind(this)}
            >
              <CloseOutlined fontSize="small" />
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
                  >
                    <CancelOutlined fontSize="small" />
                  </IconButton>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={3}>
                      <FormControl className={classes.formControl}>
                        <InputLabel>{t('Action type')}</InputLabel>
                        <Select
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
                        <InputLabel>{t('Field')}</InputLabel>
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
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseMerge.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleCloseMerge.bind(this)}
            >
              <CloseOutlined fontSize="small" />
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
              <ItemMarking label="TLP:WHITE" />
              )}
            <Alert severity="warning" style={{ marginTop: 20 }}>
              {t(
                'The relations attached to selected entities will be copied to the merged entity.',
              )}
            </Alert>
            <div className={classes.buttons}>
              <Button
                variant="contained"
                color="primary"
                onClick={this.handleLaunchMerge.bind(this)}
                classes={{ root: classes.button }}
              >
                {t('Merge')}
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
  t: PropTypes.func,
  numberOfSelectedElements: PropTypes.number,
  selectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
  filters: PropTypes.object,
  handleClearSelectedElements: PropTypes.func,
  withPaddingRight: PropTypes.bool,
};

export default R.compose(inject18n, withStyles(styles))(ToolBar);
