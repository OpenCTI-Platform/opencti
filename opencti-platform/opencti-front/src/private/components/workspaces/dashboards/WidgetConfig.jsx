/* eslint-disable custom-rules/classes-rule */
import React, { useRef, useState } from 'react';
import { v4 as uuid } from 'uuid';
import * as R from 'ramda';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Stepper from '@mui/material/Stepper';
import Step from '@mui/material/Step';
import StepButton from '@mui/material/StepButton';
import StepLabel from '@mui/material/StepLabel';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardContent from '@mui/material/CardContent';
import Button from '@mui/material/Button';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import { AddOutlined, CancelOutlined, CloudUploadOutlined, FormatShapesOutlined, LibraryBooksOutlined, MapOutlined, PieChartOutlined, WidgetsOutlined } from '@mui/icons-material';
import {
  AlignHorizontalLeft,
  ChartAreasplineVariant,
  ChartBar,
  ChartBubble,
  ChartDonut,
  ChartLine,
  ChartTimeline,
  ChartTree,
  Counter,
  DatabaseOutline,
  FlaskOutline,
  FormatListNumberedRtl,
  InformationOutline,
  Radar,
  StarSettingsOutline,
  ViewListOutline,
} from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import TextField from '@mui/material/TextField';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import Tooltip from '@mui/material/Tooltip';
import ReactMde from 'react-mde';
import SpeedDial from '@mui/material/SpeedDial';
import { SpeedDialIcon } from '@mui/material';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import ButtonGroup from '@mui/material/ButtonGroup';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';
import ClickAwayListener from '@mui/material/ClickAwayListener';
import Grow from '@mui/material/Grow';
import Paper from '@mui/material/Paper';
import Popper from '@mui/material/Popper';
import MenuList from '@mui/material/MenuList';
import { graphql } from 'react-relay';
import WidgetFilters from './WidgetFilters';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import { emptyFilterGroup, findFiltersFromKeys } from '../../../../utils/filters/filtersUtils';
import { capitalizeFirstLetter, toB64 } from '../../../../utils/String';
import { handleError, QueryRenderer } from '../../../../relay/environment';
import { stixCyberObservablesLinesAttributesQuery } from '../../observations/stix_cyber_observables/StixCyberObservablesLines';
import { isNotEmptyField } from '../../../../utils/utils';
import useHelper from '../../../../utils/hooks/useHelper';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import useAttributes from '../../../../utils/hooks/useAttributes';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Security from '../../../../utils/Security';
import { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1100,
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  speedDialButton: {
    backgroundColor: theme.palette.primary.main,
    color: theme.palette.primary.contrastText,
    '&:hover': {
      backgroundColor: theme.palette.primary.main,
    },
  },
  card: {
    height: 180,
    backgroundColor: theme.palette.background.paperLight,
    textAlign: 'center',
  },
  card3: {
    height: 100,
    backgroundColor: theme.palette.background.paperLight,
    textAlign: 'center',
  },
  formControl: {
    width: '100%',
  },
  stepCloseButton: {
    position: 'absolute',
    top: -20,
    right: -20,
  },
  add: {
    display: 'flex',
  },
  buttonAdd: {
    width: '100%',
    height: 20,
    flex: 1,
  },
  filters: {
    marginTop: 20,
  },
  filter: {
    margin: '0 10px 10px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '0 10px 10px 0',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'center',
  },
  step_entity: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.secondary.main}`,
    borderRadius: 4,
  },
  step_relationship: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.primary.main}`,
    borderRadius: 4,
  },
  step_audit: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.secondary.main}`,
    borderRadius: 4,
  },
}));

const visualizationTypes = [
  {
    key: 'text',
    name: 'Text',
    category: 'text',
    availableParameters: [],
    isRelationships: false,
    isEntities: false,
    isAudits: false,
  },
  {
    key: 'number',
    name: 'Number',
    dataSelectionLimit: 1,
    category: 'number',
    availableParameters: [],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'list',
    name: 'List',
    dataSelectionLimit: 1,
    category: 'list',
    availableParameters: [],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'distribution-list',
    name: 'List (distribution)',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'vertical-bar',
    name: 'Vertical Bar',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: ['stacked', 'legend'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'line',
    name: 'Line',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: ['legend'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'area',
    name: 'Area',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: ['stacked', 'legend'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'timeline',
    name: 'Timeline',
    dataSelectionLimit: 1,
    category: 'list',
    availableParameters: [],
    isRelationships: true,
    isEntities: true,
    isAudits: false,
  },
  {
    key: 'donut',
    name: 'Donut',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'horizontal-bar',
    name: 'Horizontal Bar',
    dataSelectionLimit: 2,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'radar',
    name: 'Radar',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'polar-area',
    name: 'Polar Area',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'heatmap',
    name: 'Heatmap',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: [],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'tree',
    name: 'Tree',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute', 'distributed'],
    isRelationships: true,
    isEntities: true,
    isAudits: true,
  },
  {
    key: 'map',
    name: 'Map',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: false,
    isAudits: false,
  },
  {
    key: 'bookmark',
    name: 'Bookmark',
    dataSelectionLimit: 1,
    category: 'timeseries',
    availableParameters: [],
    isRelationships: false,
    isEntities: true,
    isAudits: false,
  },
];
const indexedVisualizationTypes = R.indexBy(R.prop('key'), visualizationTypes);

const workspaceImportWidgetMutation = graphql`
  mutation WidgetConfigImportMutation(
    $id: ID!
    $input: ImportConfigurationInput!
  ) {
    workspaceWidgetConfigurationImport(id: $id, input: $input) {
      manifest
      ...Dashboard_workspace
    }
  }
`;

const WidgetConfig = ({ workspace, widget, onComplete, closeMenu }) => {
  let initialStep = 0;
  if (widget?.type === 'text') {
    initialStep = 3;
  } else if (widget?.dataSelection) {
    initialStep = 2;
  }
  const classes = useStyles();
  const { isFeatureEnable } = useHelper();
  const FAB_REPLACED = isFeatureEnable('FAB_REPLACEMENT');
  const { t_i18n } = useFormatter();
  const { ignoredAttributesInDashboards } = useAttributes();
  const [open, setOpen] = useState(false);
  const [selectedTab, setSelectedTab] = useState('write');
  const [stepIndex, setStepIndex] = useState(initialStep);
  const [type, setType] = useState(widget?.type ?? null);
  const inputRef = useRef();
  const widgetActionMenuAnchorRef = useRef();
  const [widgetActionSelectedIndex, setWidgetActionSelectedIndex] = useState(0);
  const [widgetActionMenuOpen, setWidgetActionMenuOpen] = React.useState(false);
  const widgetActionOptions = [
    {
      text: t_i18n('Create a Widget'),
      action: () => setOpen(true),
    },
    {
      text: t_i18n('Import a Widget'),
      action: () => inputRef.current?.click(),
    },
  ];
  const [perspective, setPerspective] = useState(widget?.perspective ?? null);
  const initialSelection = {
    label: '',
    attribute: 'entity_type',
    date_attribute: 'created_at',
    perspective: null,
    isTo: true,
    filters: emptyFilterGroup,
    dynamicFrom: emptyFilterGroup,
    dynamicTo: emptyFilterGroup,
  };
  const [dataSelection, setDataSelection] = useState(
    widget?.dataSelection ?? [initialSelection],
  );
  const [parameters, setParameters] = useState(widget?.parameters ?? {});
  const [commitWidgetImportMutation] = useApiMutation(workspaceImportWidgetMutation);
  const setDataSelectionWithIndex = (data, index) => {
    setDataSelection([...dataSelection.map((d, i) => (i === index ? data : d))]);
  };
  const handleWidgetImport = async (event) => {
    const importedWidgetConfiguration = event.target.files[0];
    const emptyDashboardManifest = toB64(JSON.stringify({ widgets: {}, config: {} }));
    const dashboardManifest = workspace.manifest ?? emptyDashboardManifest;
    commitWidgetImportMutation({
      variables: {
        id: workspace.id,
        input: {
          importType: 'widget',
          file: importedWidgetConfiguration,
          dashboardManifest,
        },
      },
      updater: () => {
        inputRef.current.value = null; // Reset the input uploader ref
      },
      onError: (error) => {
        inputRef.current.value = null; // Reset the input uploader ref
        handleError(error);
      },
    });
  };
  const handleCloseAfterCancel = () => {
    if (!widget) {
      setStepIndex(0);
      setType(null);
      setPerspective(null);
      setDataSelection([initialSelection]);
      setParameters({});
    } else if (widget.type === 'text') {
      setStepIndex(3);
    } else {
      setStepIndex(2);
    }
    setOpen(false);
    setDataSelection(widget?.dataSelection ?? [initialSelection]);
  };

  const handleCloseAfterUpdate = () => {
    if (!widget) {
      setStepIndex(0);
      setType(null);
      setPerspective(null);
      setDataSelection([initialSelection]);
      setParameters({});
    } else if (widget.type === 'text') {
      setStepIndex(3);
    } else {
      setStepIndex(2);
    }
    setOpen(false);
  };
  const completeSetup = () => {
    onComplete({
      ...(widget ?? {}),
      id: widget?.id ?? uuid(),
      type,
      perspective,
      dataSelection,
      parameters,
    });
    handleCloseAfterUpdate();
  };
  const getCurrentIsRelationships = () => {
    return indexedVisualizationTypes[type]?.isRelationships ?? false;
  };
  const isWidgetListOrTimeline = () => {
    return indexedVisualizationTypes[type]?.key === 'list' || indexedVisualizationTypes[type]?.key === 'timeline';
  };
  const getCurrentIsEntities = () => {
    return indexedVisualizationTypes[type]?.isEntities ?? false;
  };
  const getCurrentIsAudits = () => {
    return indexedVisualizationTypes[type]?.isAudits ?? false;
  };
  const getCurrentDataSelectionLimit = () => {
    return indexedVisualizationTypes[type]?.dataSelectionLimit ?? 0;
  };
  const getCurrentCategory = () => {
    return indexedVisualizationTypes[type]?.category ?? 'none';
  };
  const getCurrentAvailableParameters = () => {
    return indexedVisualizationTypes[type]?.availableParameters ?? [];
  };
  const getCurrentSelectedEntityTypes = (index) => {
    return R.uniq(
      findFiltersFromKeys(dataSelection[index]?.filters?.filters ?? [], [
        'fromTypes',
        'toTypes',
        'entity_type',
      ])
        .map((f) => f.values)
        .flat(),
    );
  };
  const handleSelectType = (selectedType) => {
    setType(selectedType);
    if (selectedType === 'text') {
      setStepIndex(3);
    } else {
      setStepIndex(1);
    }
  };
  const handleSelectPerspective = (selectedPerspective) => {
    const newDataSelection = dataSelection.map((n) => ({
      ...n,
      perspective: selectedPerspective,
      filters: selectedPerspective === n.perspective ? n.filters : emptyFilterGroup,
      dynamicFrom: selectedPerspective === n.perspective ? n.dynamicFrom : emptyFilterGroup,
      dynamicTo: selectedPerspective === n.perspective ? n.dynamicTo : emptyFilterGroup,
    }));
    setDataSelection(newDataSelection);
    setPerspective(selectedPerspective);
    setStepIndex(2);
  };
  const handleAddDataSelection = (subPerspective) => {
    setDataSelection([
      ...dataSelection,
      {
        label: '',
        attribute: 'entity_type',
        date_attribute: 'created_at',
        perspective: subPerspective,
        filters: emptyFilterGroup,
        dynamicFrom: emptyFilterGroup,
        dynamicTo: emptyFilterGroup,
      },
    ]);
  };
  const handleRemoveDataSelection = (i) => {
    const newDataSelection = Array.from(dataSelection);
    newDataSelection.splice(i, 1);
    setDataSelection(newDataSelection);
  };
  const isDataSelectionFiltersValid = () => {
    return dataSelection.length > 0;
  };
  const isDataSelectionAttributesValid = () => {
    for (const n of dataSelection) {
      if (n.attribute.length === 0) {
        return false;
      }
    }
    return true;
  };
  const handleChangeDataValidationLabel = (i, value) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return { ...data, label: value };
      }
      return data;
    });
    setDataSelection(newDataSelection);
  };

  const handleChangeDataValidationParameter = (
    i,
    key,
    value,
    number = false,
  ) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return {
          ...data,
          [key]: number ? parseInt(value, 10) : value,
        };
      }
      return data;
    });
    setDataSelection(newDataSelection);
  };
  const handleToggleDataValidationIsTo = (i) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return { ...data, isTo: !data.isTo };
      }
      return data;
    });
    setDataSelection(newDataSelection);
  };
  const handleToggleParameter = (parameter) => {
    setParameters({ ...parameters, [parameter]: !parameters[parameter] });
  };
  const handleChangeParameter = (parameter, value) => {
    setParameters({ ...parameters, [parameter]: value });
  };
  const handleWidgetActionClick = () => {
    widgetActionOptions[widgetActionSelectedIndex].action();
  };
  const handleToggleWidgetActionMenuOpen = () => {
    setWidgetActionMenuOpen(!widgetActionMenuOpen);
  };
  const handleWidgetActionMenuItemClick = (event, index) => {
    setWidgetActionSelectedIndex(index);
    setWidgetActionMenuOpen(false);
  };
  const handleWidgetActionMenuClose = (event) => {
    if (widgetActionMenuAnchorRef.current && widgetActionMenuAnchorRef.current.contains(event.target)) {
      return;
    }
    setWidgetActionMenuOpen(false);
  };
  const renderIcon = (key) => {
    switch (key) {
      case 'map':
        return <MapOutlined fontSize="large" color="primary"/>;
      case 'horizontal-bar':
        return <AlignHorizontalLeft fontSize="large" color="primary"/>;
      case 'vertical-bar':
        return <ChartBar fontSize="large" color="primary"/>;
      case 'donut':
        return <ChartDonut fontSize="large" color="primary"/>;
      case 'area':
        return <ChartAreasplineVariant fontSize="large" color="primary"/>;
      case 'timeline':
        return <ChartTimeline fontSize="large" color="primary"/>;
      case 'list':
        return <ViewListOutline fontSize="large" color="primary"/>;
      case 'distribution-list':
        return <FormatListNumberedRtl fontSize="large" color="primary"/>;
      case 'number':
        return <Counter fontSize="large" color="primary"/>;
      case 'text':
        return <FormatShapesOutlined fontSize="large" color="primary"/>;
      case 'heatmap':
        return <ChartBubble fontSize="large" color="primary"/>;
      case 'line':
        return <ChartLine fontSize="large" color="primary"/>;
      case 'radar':
        return <Radar fontSize="large" color="primary"/>;
      case 'polar-area':
        return <PieChartOutlined fontSize="large" color="primary"/>;
      case 'tree':
        return <ChartTree fontSize="large" color="primary"/>;
      case 'bookmark':
        return <StarSettingsOutline fontSize="large" color="primary"/>;
      default:
        return 'Go away';
    }
  };
  const renderTypes = () => {
    return (
      <Grid
        container={true}
        spacing={3}
        style={{ marginTop: 20, marginBottom: 20 }}
      >
        {visualizationTypes.map((visualizationType) => (
          <Grid key={visualizationType.key} item={true} xs={4}>
            <Card variant="outlined" className={classes.card3}>
              <CardActionArea
                onClick={() => handleSelectType(visualizationType.key)}
                style={{ height: '100%' }}
                aria-label={t_i18n(visualizationType.name)}
              >
                <CardContent>
                  {renderIcon(visualizationType.key)}
                  <Typography
                    gutterBottom
                    variant="body1"
                    style={{ marginTop: 8 }}
                  >
                    {t_i18n(visualizationType.name)}
                  </Typography>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>
    );
  };
  const renderPerspective = () => {
    let xs = 12;
    if (
      getCurrentIsEntities()
            && getCurrentIsRelationships()
            && getCurrentIsAudits()
    ) {
      xs = 4;
    } else if (getCurrentIsEntities() && getCurrentIsRelationships()) {
      xs = 6;
    }
    return (
      <Grid
        container={true}
        spacing={3}
        style={{ marginTop: 20, marginBottom: 20 }}
      >
        {getCurrentIsEntities() && (
        <Grid item={true} xs={xs}>
          <Card variant="outlined" className={classes.card}>
            <CardActionArea
              onClick={() => handleSelectPerspective('entities')}
              style={{ height: '100%' }}
              aria-label={t_i18n('Entities')}
            >
              <CardContent>
                <DatabaseOutline style={{ fontSize: 40 }} color="primary"/>
                <Typography
                  gutterBottom
                  variant="h2"
                  style={{ marginTop: 20 }}
                >
                  {t_i18n('Entities')}
                </Typography>
                <br/>
                <Typography variant="body1">
                  {t_i18n('Display global knowledge with filters and criteria.')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        )}
        {getCurrentIsRelationships() && (
        <Grid item={true} xs={xs}>
          <Card variant="outlined" className={classes.card}>
            <CardActionArea
              onClick={() => handleSelectPerspective('relationships')}
              style={{ height: '100%' }}
              aria-label={t_i18n('Knowledge graph')}
            >
              <CardContent>
                <FlaskOutline style={{ fontSize: 40 }} color="primary"/>
                <Typography
                  gutterBottom
                  variant="h2"
                  style={{ marginTop: 20 }}
                >
                  {t_i18n('Knowledge graph')}
                </Typography>
                <br/>
                <Typography variant="body1">
                  {t_i18n(
                    'Display specific knowledge using relationships and filters.',
                  )}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        )}
        {getCurrentIsAudits() && (
        <Grid item={true} xs={xs}>
          <Card variant="outlined" className={classes.card}>
            <CardActionArea
              onClick={() => handleSelectPerspective('audits')}
              style={{ height: '100%' }}
              aria-label={t_i18n('Activity & history')}
            >
              <CardContent>
                <LibraryBooksOutlined
                  style={{ fontSize: 40 }}
                  color="primary"
                />
                <Typography
                  gutterBottom
                  variant="h2"
                  style={{ marginTop: 20 }}
                >
                  {t_i18n('Activity & history')}
                </Typography>
                <br/>
                <Typography variant="body1">
                  {t_i18n('Display data related to the history and activity.')}
                </Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>
        )}
      </Grid>
    );
  };
  const renderDataSelection = () => {
    return (
      <div style={{ marginTop: 20 }}>
        {Array(dataSelection.length)
          .fill(0)
          .map((_, i) => {
            let style = 'step_entity';
            if (dataSelection[i].perspective === 'relationships') {
              style = 'step_relationship';
            } else if (dataSelection[i].perspective === 'audits') {
              style = 'step_audit';
            }
            return (
              <div key={i} className={classes[style]}>
                <IconButton
                  disabled={dataSelection.length === 1}
                  aria-label="Delete"
                  className={classes.stepCloseButton}
                  onClick={() => handleRemoveDataSelection(i)}
                  size="large"
                >
                  <CancelOutlined fontSize="small" />
                </IconButton>
                <div style={{ display: 'flex', width: '100%' }}>
                  <TextField
                    style={{ flex: 1 }}
                    label={`${t_i18n('Label')} (${dataSelection[i].perspective})`}
                    fullWidth={true}
                    value={dataSelection[i].label}
                    onChange={(event) => handleChangeDataValidationLabel(i, event.target.value)}
                  />
                  {perspective === 'relationships'
                    && <Tooltip
                      title={t_i18n(
                        'The relationships taken into account are: stix core relationships, sightings and \'contains\' relationships',
                      )}
                       >
                      <InformationOutline
                        fontSize="small"
                        color="primary"
                        style={{ marginRight: 5, marginTop: 20 }}
                      />
                    </Tooltip>}
                </div>
                <WidgetFilters
                  dataSelection={dataSelection[i]}
                  setDataSelection={(data) => setDataSelectionWithIndex(data, i)}
                  perspective={dataSelection[i].perspective ?? perspective}
                  type={type}
                />
              </div>
            );
          })}
        {perspective === 'entities' && (
          <div className={classes.add}>
            <Button
              variant="contained"
              disabled={getCurrentDataSelectionLimit() === dataSelection.length}
              color="secondary"
              size="small"
              onClick={() => handleAddDataSelection('entities')}
              classes={{ root: classes.buttonAdd }}
            >
              <AddOutlined fontSize="small" />
            </Button>
          </div>
        )}
        {perspective === 'relationships' && (
          <div className={classes.add}>
            <Button
              style={{ marginRight: 20 }}
              variant="contained"
              disabled={getCurrentDataSelectionLimit() === dataSelection.length}
              size="small"
              onClick={() => handleAddDataSelection('relationships')}
              classes={{ root: classes.buttonAdd }}
            >
              <AddOutlined fontSize="small" /> {t_i18n('Relationships')}
            </Button>
            <Button
              variant="contained"
              disabled={getCurrentDataSelectionLimit() === dataSelection.length}
              color="secondary"
              size="small"
              onClick={() => handleAddDataSelection('entities')}
              classes={{ root: classes.buttonAdd }}
            >
              <AddOutlined fontSize="small" /> {t_i18n('Entities')}
            </Button>
          </div>
        )}
        {perspective === 'audits' && (
          <div className={classes.add}>
            <Button
              variant="contained"
              disabled={
                getCurrentDataSelectionLimit() === dataSelection.length
                || getCurrentCategory() === 'distribution'
              }
              color="secondary"
              size="small"
              onClick={() => handleAddDataSelection('audits')}
              classes={{ root: classes.buttonAdd }}
            >
              <AddOutlined fontSize="small" />
            </Button>
          </div>
        )}
        <div className={classes.buttons}>
          <Button
            disabled={!isDataSelectionFiltersValid()}
            variant="contained"
            color="primary"
            classes={{ root: classes.button }}
            onClick={() => setStepIndex(3)}
          >
            {t_i18n('Validate')}
          </Button>
        </div>
      </div>
    );
  };
  const renderParameters = () => {
    return (
      <div style={{ marginTop: 20 }}>
        <TextField
          label={t_i18n('Title')}
          fullWidth={true}
          value={parameters.title}
          onChange={(event) => handleChangeParameter('title', event.target.value)
                    }
        />
        {getCurrentCategory() === 'text' && (
        <div style={{ marginTop: 20 }}>
          <InputLabel shrink={true}>{t_i18n('Content')}</InputLabel>
          <ReactMde
            value={parameters.content}
            onChange={(value) => handleChangeParameter('content', value)}
            selectedTab={selectedTab}
            onTabChange={(tab) => setSelectedTab(tab)}
            generateMarkdownPreview={(markdown) => Promise.resolve(
              <MarkdownDisplay
                content={markdown}
                remarkGfmPlugin={true}
                commonmark={true}
              />,
            )}
            l18n={{
              write: t_i18n('Write'),
              preview: t_i18n('Preview'),
              uploadingImage: t_i18n('Uploading image'),
              pasteDropSelect: t_i18n('Paste'),
            }}
            minEditorHeight={100}
            maxEditorHeight={100}
          />
        </div>
        )}
        {getCurrentCategory() === 'timeseries' && (
        <FormControl fullWidth={true} style={{ marginTop: 20 }}>
          <InputLabel id="relative">{t_i18n('Interval')}</InputLabel>
          <Select
            labelId="relative"
            fullWidth={true}
            value={parameters.interval ?? 'day'}
            onChange={(event) => handleChangeParameter('interval', event.target.value)
                            }
          >
            <MenuItem value="day">{t_i18n('Day')}</MenuItem>
            <MenuItem value="week">{t_i18n('Week')}</MenuItem>
            <MenuItem value="month">{t_i18n('Month')}</MenuItem>
            <MenuItem value="quarter">{t_i18n('Quarter')}</MenuItem>
            <MenuItem value="year">{t_i18n('Year')}</MenuItem>
          </Select>
        </FormControl>
        )}
        <>
          {Array(dataSelection.length)
            .fill(0)
            .map((_, i) => {
              return (
                <div key={i}>
                  {(getCurrentCategory() === 'distribution'
                    || getCurrentCategory() === 'list') && (
                    <TextField
                      label={t_i18n('Number of results')}
                      fullWidth={true}
                      type="number"
                      value={dataSelection[i].number ?? 10}
                      onChange={(event) => handleChangeDataValidationParameter(
                        i,
                        'number',
                        event.target.value,
                        true,
                      )
                        }
                      style={{ marginTop: 20 }}
                    />
                  )}
                  {dataSelection[i].perspective !== 'audits' && (
                  <div
                    style={{
                      display: 'flex',
                      width: '100%',
                      marginTop: 20,
                    }}
                  >
                    <FormControl fullWidth={true} style={{ flex: 1 }}>
                      <InputLabel id="relative" size="small">
                        {isNotEmptyField(dataSelection[i].label)
                          ? dataSelection[i].label
                          : t_i18n('Date attribute')}
                      </InputLabel>
                      <Select
                        labelId="relative"
                        size="small"
                        fullWidth={true}
                        value={dataSelection[i].date_attribute ?? 'created_at'}
                        onChange={(event) => handleChangeDataValidationParameter(i, 'date_attribute', event.target.value)}
                      >
                        <MenuItem value="created_at">
                          created_at ({t_i18n('Technical date')})
                        </MenuItem>
                        <MenuItem value="updated_at">
                          updated_at ({t_i18n('Technical date')})
                        </MenuItem>
                        <MenuItem value="created">
                          created ({t_i18n('Functional date')})
                        </MenuItem>
                        <MenuItem value="modified">
                          modified ({t_i18n('Functional date')})
                        </MenuItem>
                        {getCurrentIsRelationships() && (
                        <MenuItem value="start_time">
                          start_time ({t_i18n('Functional date')})
                        </MenuItem>
                        )}
                        {getCurrentIsRelationships() && (
                        <MenuItem value="stop_time">
                          stop_time ({t_i18n('Functional date')})
                        </MenuItem>
                        )}
                        {getCurrentIsRelationships() && !isWidgetListOrTimeline() && (
                        <MenuItem value="first_seen">
                          first_seen ({t_i18n('Functional date')})
                        </MenuItem>
                        )}
                        {getCurrentIsRelationships() && !isWidgetListOrTimeline() && (
                        <MenuItem value="last_seen">
                          last_seen ({t_i18n('Functional date')})
                        </MenuItem>
                        )}
                      </Select>
                    </FormControl>
                  </div>
                  )}
                  {dataSelection[i].perspective === 'relationships'
                    && type === 'map' && (
                    <TextField
                      label={t_i18n('Zoom')}
                      fullWidth={true}
                      value={dataSelection[i].zoom ?? 2}
                      placeholder={t_i18n('Zoom')}
                      onChange={(event) => handleChangeDataValidationParameter(
                        i,
                        'zoom',
                        event.target.value,
                      )
                            }
                      style={{ marginTop: 20 }}
                    />
                  )}
                  {dataSelection[i].perspective === 'relationships'
                    && type === 'map' && (
                    <TextField
                      label={t_i18n('Center latitude')}
                      fullWidth={true}
                      value={dataSelection[i].centerLat ?? 48.8566969}
                      placeholder={t_i18n('Center latitude')}
                      onChange={(event) => handleChangeDataValidationParameter(
                        i,
                        'centerLat',
                        event.target.value,
                      )
                            }
                      style={{ marginTop: 20 }}
                    />
                  )}
                  {dataSelection[i].perspective === 'relationships'
                    && type === 'map' && (
                    <TextField
                      label={t_i18n('Center longitude')}
                      fullWidth={true}
                      value={dataSelection[i].centerLng ?? 2.3514616}
                      placeholder={t_i18n('Center longitude')}
                      onChange={(event) => handleChangeDataValidationParameter(
                        i,
                        'centerLng',
                        event.target.value,
                      )
                            }
                      style={{ marginTop: 20 }}
                    />
                  )}
                  {getCurrentAvailableParameters().includes('attribute') && (
                  <div
                    style={{ display: 'flex', width: '100%', marginTop: 20 }}
                  >
                    {dataSelection[i].perspective === 'relationships' && (
                    <FormControl
                      className={classes.formControl}
                      fullWidth={true}
                      style={{
                        flex: 1,
                        marginRight: 20,
                      }}
                    >
                      <InputLabel>{t_i18n('Attribute')}</InputLabel>
                      <Select
                        fullWidth={true}
                        value={dataSelection[i].attribute}
                        onChange={(event) => handleChangeDataValidationParameter(
                          i,
                          'attribute',
                          event.target.value,
                        )
                                                        }
                      >
                        <MenuItem key="internal_id" value="internal_id">
                          {t_i18n('Entity')}
                        </MenuItem>
                        <MenuItem key="entity_type" value="entity_type">
                          {t_i18n('Entity type')}
                        </MenuItem>
                        <MenuItem
                          key="created-by.internal_id"
                          value="created-by.internal_id"
                        >
                          {t_i18n('Author')}
                        </MenuItem>
                        <MenuItem
                          key="object-marking.internal_id"
                          value="object-marking.internal_id"
                        >
                          {t_i18n('Marking definition')}
                        </MenuItem>
                        <MenuItem
                          key="kill-chain-phase.internal_id"
                          value="kill-chain-phase.internal_id"
                        >
                          {t_i18n('Kill chain phase')}
                        </MenuItem>
                        <MenuItem key="creator_id" value="creator_id">
                          {t_i18n('Creator')}
                        </MenuItem>
                        <MenuItem key="x_opencti_workflow_id" value="x_opencti_workflow_id">
                          {t_i18n('Status')}
                        </MenuItem>
                      </Select>
                    </FormControl>
                    )}
                    {dataSelection[i].perspective === 'entities'
                      && getCurrentSelectedEntityTypes(i).length > 0
                      && (
                      <FormControl
                        className={classes.formControl}
                        fullWidth={true}
                        style={{
                          flex: 1,
                        }}
                      >
                        <InputLabel>{t_i18n('Attribute')}</InputLabel>
                        <QueryRenderer
                          query={stixCyberObservablesLinesAttributesQuery}
                          variables={{
                            elementType: getCurrentSelectedEntityTypes(i),
                          }}
                          render={({ props: resultProps }) => {
                            if (resultProps
                              && resultProps.schemaAttributeNames
                            ) {
                              let attributesValues = (resultProps.schemaAttributeNames.edges)
                                .map((n) => n.node.value)
                                .filter(
                                  (n) => !R.includes(
                                    n,
                                    ignoredAttributesInDashboards,
                                  ) && !n.startsWith('i_'),
                                );
                              if (
                                attributesValues.filter((n) => n === 'hashes').length > 0
                              ) {
                                attributesValues = [
                                  ...attributesValues,
                                  'hashes.MD5',
                                  'hashes.SHA-1',
                                  'hashes.SHA-256',
                                  'hashes.SHA-512',
                                ].filter((n) => n !== 'hashes').sort();
                              }
                              return (
                                <Select
                                  fullWidth={true}
                                  value={dataSelection[i].attribute}
                                  onChange={(event) => handleChangeDataValidationParameter(
                                    i,
                                    'attribute',
                                    event.target.value,
                                  )
                                                  }
                                >
                                  {[
                                    ...attributesValues,
                                    'created-by.internal_id',
                                    'object-label.internal_id',
                                    'object-assignee.internal_id',
                                    'object-marking.internal_id',
                                    'kill-chain-phase.internal_id',
                                    'x_opencti_workflow_id',
                                  ].map((value) => (
                                    <MenuItem
                                      key={value}
                                      value={value}
                                    >
                                      {t_i18n(
                                        capitalizeFirstLetter(
                                          value,
                                        ),
                                      )}
                                    </MenuItem>
                                  ))}
                                </Select>
                              );
                            }
                            return <div/>;
                          }}
                        />
                      </FormControl>
                      )}
                    {dataSelection[i].perspective === 'entities'
                      && getCurrentSelectedEntityTypes(i).length === 0 && (
                        <FormControl
                          className={classes.formControl}
                          fullWidth={true}
                          style={{
                            flex: 1,
                            marginRight: 20,
                          }}
                        >
                          <InputLabel>{t_i18n('Attribute')}</InputLabel>
                          <Select
                            fullWidth={true}
                            value={dataSelection[i].attribute ?? 'entity_type'}
                            onChange={(event) => handleChangeDataValidationParameter(
                              i,
                              'attribute',
                              event.target.value,
                            )
                          }
                          >
                            {[
                              'entity_type',
                              'created-by.internal_id',
                              'object-label.internal_id',
                              'object-assignee.internal_id',
                              'object-marking.internal_id',
                              'kill-chain-phase.internal_id',
                              'x_opencti_workflow_id',
                            ].map((value) => (
                              <MenuItem
                                key={value}
                                value={value}
                              >
                                {t_i18n(capitalizeFirstLetter(value))}
                              </MenuItem>
                            ))}
                          </Select>
                        </FormControl>
                    )}
                    {dataSelection[i].perspective === 'audits' && (
                    <FormControl
                      className={classes.formControl}
                      fullWidth={true}
                      style={{
                        flex: 1,
                      }}
                    >
                      <InputLabel>{t_i18n('Attribute')}</InputLabel>
                      <Select
                        fullWidth={true}
                        value={dataSelection[i].attribute ?? 'entity_type'}
                        onChange={(event) => handleChangeDataValidationParameter(
                          i,
                          'attribute',
                          event.target.value,
                        )
                        }
                      >
                        {['entity_type',
                          'context_data.id',
                          'context_data.created_by_ref_id',
                          'context_data.labels_ids',
                          'context_data.object_marking_refs_ids',
                          'context_data.creator_ids',
                          'context_data.search',
                          'event_type',
                          'event_scope',
                          'user_id',
                          'group_ids',
                          'organization_ids',
                        ].map((value) => (
                          <MenuItem
                            key={value}
                            value={value}
                          >
                            {t_i18n(capitalizeFirstLetter(value))}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                    )}
                    {dataSelection[i].perspective === 'relationships' && (
                    <FormControlLabel
                      control={
                        <Switch
                          onChange={() => handleToggleDataValidationIsTo(i)}
                          checked={!dataSelection[i].isTo}
                        />
                      }
                      label={t_i18n('Display the source')}
                    />
                    )}
                    {dataSelection[i].perspective === 'relationships' && (
                    <Tooltip
                      title={t_i18n(
                        'Enable if the displayed data is the source of the relationships.',
                      )}
                    >
                      <InformationOutline
                        fontSize="small"
                        color="primary"
                        style={{ marginTop: 14 }}
                      />
                    </Tooltip>
                    )}
                  </div>
                  )}
                </div>
              );
            })}
        </>
        <div style={{ display: 'flex', width: '100%', marginTop: 20 }}>
          {getCurrentAvailableParameters().includes('stacked') && (
          <FormControlLabel
            control={
              <Switch
                onChange={() => handleToggleParameter('stacked')}
                checked={parameters.stacked}
              />
            }
            label={t_i18n('Stacked')}
          />
          )}
          {getCurrentAvailableParameters().includes('distributed') && (
          <FormControlLabel
            control={
              <Switch
                onChange={() => handleToggleParameter('distributed')}
                checked={parameters.distributed}
              />
            }
            label={t_i18n('Distributed')}
          />
          )}
          {getCurrentAvailableParameters().includes('legend') && (
          <FormControlLabel
            control={
              <Switch
                onChange={() => handleToggleParameter('legend')}
                checked={parameters.legend}
              />
            }
            label={t_i18n('Display legend')}
          />
          )}
        </div>
      </div>
    );
  };
  const getStepContent = () => {
    switch (stepIndex) {
      case 0:
        return renderTypes();
      case 1:
        return renderPerspective();
      case 2:
        return renderDataSelection();
      case 3:
        return renderParameters();
      default:
        return 'Go away!';
    }
  };

  return (
    <>
      {!widget && (
        <>
          <VisuallyHiddenInput type="file" accept={'application/JSON'} ref={inputRef} onChange={handleWidgetImport} />
          <Security needs={[EXPLORE_EXUPDATE]}>
          {FAB_REPLACED && (
            <div>
              <ButtonGroup
                variant='contained'
                ref={widgetActionMenuAnchorRef}
                disableElevation
              >
                <Button onClick={handleWidgetActionClick}>
                  {widgetActionOptions[widgetActionSelectedIndex].text}
                </Button>
                <Button
                  size='small'
                  onClick={handleToggleWidgetActionMenuOpen}
                  data-testid="widget-action-selection"
                >
                  <ArrowDropDownIcon/>
                </Button>
              </ButtonGroup>
              <Popper
                sx={{ zIndex: 1 }}
                open={widgetActionMenuOpen}
                anchorEl={widgetActionMenuAnchorRef.current}
                role={undefined}
                transition
                disablePortal
              >
                {({ TransitionProps, placement }) => (
                  <Grow
                    {...TransitionProps}
                    style={{
                      transformOrigin:
                        placement === 'bottom' ? 'center top' : 'center bottom',
                    }}
                  >
                    <Paper>
                      <ClickAwayListener onClickAway={handleWidgetActionMenuClose}>
                        <MenuList id="split-button-menu" autoFocusItem>
                          {widgetActionOptions.map((option, index) => (
                            <MenuItem
                              key={option}
                              selected={index === widgetActionSelectedIndex}
                              onClick={(event) => handleWidgetActionMenuItemClick(event, index)}
                            >
                              {option.text}
                            </MenuItem>
                          ))}
                        </MenuList>
                      </ClickAwayListener>
                    </Paper>
                  </Grow>
                )}
              </Popper>
            </div>
          )
         }
          {!FAB_REPLACED && (
          <SpeedDial
            className={classes.createButton}
            ariaLabel="Create"
            icon={<SpeedDialIcon />}
            FabProps={{ color: 'primary' }}
          >
            <SpeedDialAction
              title={t_i18n('Create a widget')}
              icon={<WidgetsOutlined />}
              tooltipTitle={t_i18n('Create a widget')}
              onClick={() => setOpen(true)}
              FabProps={{ classes: { root: classes.speedDialButton } }}
            />
            <SpeedDialAction
              title={t_i18n('Import a widget')}
              icon={<CloudUploadOutlined />}
              tooltipTitle={t_i18n('Import a widget')}
              onClick={() => inputRef.current?.click()}
              FabProps={{ classes: { root: classes.speedDialButton } }}
            />
          </SpeedDial>
          )
        }
          </Security>
        </>
      )}
      {widget && (
        <MenuItem
          onClick={() => {
            closeMenu();
            setOpen(true);
          }}
        >
          {t_i18n('Update')}
        </MenuItem>
      )}
      <Dialog
        open={open}
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        onClose={handleCloseAfterCancel}
        fullWidth={true}
        maxWidth="md"
        className="noDrag"
      >
        <DialogTitle>
          <Stepper nonLinear activeStep={stepIndex}>
            <Step>
              <StepButton
                onClick={() => setStepIndex(0)}
                disabled={stepIndex === 0}
              >
                <StepLabel>{t_i18n('Visualization')}</StepLabel>
              </StepButton>
            </Step>
            <Step>
              <StepButton
                onClick={() => setStepIndex(1)}
                disabled={stepIndex <= 1 || getCurrentCategory() === 'text'}
              >
                <StepLabel>{t_i18n('Perspective')}</StepLabel>
              </StepButton>
            </Step>
            <Step>
              <StepButton
                onClick={() => setStepIndex(2)}
                disabled={stepIndex <= 2 || getCurrentCategory() === 'text'}
              >
                <StepLabel>{t_i18n('Filters')}</StepLabel>
              </StepButton>
            </Step>
            <Step>
              <StepButton
                onClick={() => setStepIndex(3)}
                disabled={stepIndex <= 3}
              >
                <StepLabel>{t_i18n('Parameters')}</StepLabel>
              </StepButton>
            </Step>
          </Stepper>
        </DialogTitle>
        <DialogContent>{getStepContent()}</DialogContent>
        <DialogActions>
          <Button onClick={handleCloseAfterCancel}>{t_i18n('Cancel')}</Button>
          <Button
            color="secondary"
            onClick={completeSetup}
            disabled={
              stepIndex !== 3
              || (getCurrentAvailableParameters().includes('attribute')
                && !isDataSelectionAttributesValid())
            }
            data-testid="widget-submit-button"
          >
            {widget ? t_i18n('Update') : t_i18n('Create')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default WidgetConfig;
