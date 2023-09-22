import React, { useState } from 'react';
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
import InputAdornment from '@mui/material/InputAdornment';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardContent from '@mui/material/CardContent';
import Button from '@mui/material/Button';
import Fab from '@mui/material/Fab';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import {
  Add,
  AddOutlined,
  CancelOutlined,
  MapOutlined,
  LibraryBooksOutlined,
  FormatShapesOutlined,
} from '@mui/icons-material';
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
  InformationOutline,
  Radar,
  ViewListOutline,
  StarSettingsOutline,
  FormatListNumberedRtl,
} from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import TextField from '@mui/material/TextField';
import Chip from '@mui/material/Chip';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import Tooltip from '@mui/material/Tooltip';
import ReactMde from 'react-mde';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import { ignoredAttributesInDashboards } from '../../../../utils/hooks/useAttributes';
import Filters from '../../common/lists/Filters';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import { capitalizeFirstLetter, truncate } from '../../../../utils/String';
import { QueryRenderer } from '../../../../relay/environment';
import { stixCyberObservablesLinesAttributesQuery } from '../../observations/stix_cyber_observables/StixCyberObservablesLines';
import { isNotEmptyField } from '../../../../utils/utils';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const useStyles = makeStyles((theme) => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1001,
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
}));

const entitiesFilters = [
  'entity_type',
  'elementId',
  'markedBy',
  'labelledBy',
  'createdBy',
  'creator',
  'x_opencti_workflow_id',
  'assigneeTo',
  'participant',
  'objectContains',
  'x_opencti_score',
  'x_opencti_detection',
  'revoked',
  'confidence',
  'pattern_type',
  'killChainPhase',
  'malware_types',
  'report_types',
  'relationship_type',
];

const relationshipsFilters = [
  'fromId',
  'toId',
  'fromTypes',
  'toTypes',
  'relationship_type',
  'markedBy',
  'labelledBy',
  'createdBy',
  'confidence',
  'killChainPhase',
  'creator',
];

const auditsFilters = [
  'entity_type',
  'elementId',
  'event_type',
  'event_scope',
  'members_group',
  'members_organization',
  'members_user',
];

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
    key: 'heatmap',
    name: 'Heatmap',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: ['stacked', 'legend'],
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

const WidgetConfig = ({ widget, onComplete, closeMenu }) => {
  let initialStep = 0;
  if (widget?.type === 'text') {
    initialStep = 3;
  } else if (widget?.dataSelection) {
    initialStep = 2;
  }
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const [selectedTab, setSelectedTab] = useState('write');
  const [stepIndex, setStepIndex] = useState(initialStep);
  const [type, setType] = useState(widget?.type ?? null);
  const [perspective, setPerspective] = useState(widget?.perspective ?? null);
  const initialSelection = {
    label: '',
    attribute: 'entity_type',
    date_attribute: 'created_at',
    perspective: null,
    isTo: true,
    filters: {},
    dynamicFrom: {},
    dynamicTo: {},
  };
  const [dataSelection, setDataSelection] = useState(
    widget?.dataSelection ?? [initialSelection],
  );
  const [parameters, setParameters] = useState(widget?.parameters ?? {});
  const handleClose = () => {
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
    handleClose();
  };
  const getCurrentIsRelationships = () => {
    return indexedVisualizationTypes[type]?.isRelationships ?? false;
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
      R.values(
        R.pick(
          ['fromTypes', 'toTypes', 'entity_type'],
          dataSelection[index].filters,
        ),
      )
        .flat()
        .map((n) => n.id),
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
        filters: {},
        dynamicFrom: {},
        dynamicTo: {},
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
        return { ...dataSelection[i], label: value };
      }
      return data;
    });
    setDataSelection(newDataSelection);
  };
  const handleAddDataValidationFilter = (i, key, id, value) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        if (
          dataSelection[i].filters[key]
          && dataSelection[i].filters[key].length > 0
        ) {
          return {
            ...dataSelection[i],
            filters: R.assoc(
              key,
              isUniqFilter(key)
                ? [{ id, value }]
                : R.uniqBy(R.prop('id'), [
                  { id, value },
                  ...dataSelection[i].filters[key],
                ]),
              dataSelection[i].filters,
            ),
          };
        }
        return {
          ...dataSelection[i],
          filters: R.assoc(key, [{ id, value }], dataSelection[i].filters),
        };
      }
      return data;
    });
    setDataSelection(newDataSelection);
  };
  const handleRemoveDataSelectionFilter = (i, key) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return {
          ...dataSelection[i],
          filters: R.dissoc(key, dataSelection[i].filters),
        };
      }
      return data;
    });
    setDataSelection(newDataSelection);
  };
  const handleAddDataValidationDynamicFrom = (i, key, id, value) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        if (
          dataSelection[i].dynamicFrom[key]
          && dataSelection[i].dynamicFrom[key].length > 0
        ) {
          return {
            ...dataSelection[i],
            dynamicFrom: R.assoc(
              key,
              isUniqFilter(key)
                ? [{ id, value }]
                : R.uniqBy(R.prop('id'), [
                  { id, value },
                  ...dataSelection[i].dynamicFrom[key],
                ]),
              dataSelection[i].dynamicFrom,
            ),
          };
        }
        return {
          ...dataSelection[i],
          dynamicFrom: R.assoc(
            key,
            [{ id, value }],
            dataSelection[i].dynamicFrom,
          ),
        };
      }
      return data;
    });
    setDataSelection(newDataSelection);
  };
  const handleRemoveDataSelectionDynamicFrom = (i, key) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return {
          ...dataSelection[i],
          dynamicFrom: R.dissoc(key, dataSelection[i].dynamicFrom),
        };
      }
      return data;
    });
    setDataSelection(newDataSelection);
  };
  const handleAddDataValidationDynamicTo = (i, key, id, value) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        if (
          dataSelection[i].dynamicTo[key]
          && dataSelection[i].dynamicTo[key].length > 0
        ) {
          return {
            ...dataSelection[i],
            dynamicTo: R.assoc(
              key,
              isUniqFilter(key)
                ? [{ id, value }]
                : R.uniqBy(R.prop('id'), [
                  { id, value },
                  ...dataSelection[i].dynamicTo[key],
                ]),
              dataSelection[i].dynamicTo,
            ),
          };
        }
        return {
          ...dataSelection[i],
          dynamicTo: R.assoc(key, [{ id, value }], dataSelection[i].dynamicTo),
        };
      }
      return data;
    });
    setDataSelection(newDataSelection);
  };
  const handleRemoveDataSelectionDynamicTo = (i, key) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return {
          ...dataSelection[i],
          dynamicTo: R.dissoc(key, dataSelection[i].dynamicTo),
        };
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
          ...dataSelection[i],
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
        return { ...dataSelection[i], isTo: !dataSelection[i].isTo };
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
  const renderIcon = (key) => {
    switch (key) {
      case 'map':
        return <MapOutlined fontSize="large" color="primary" />;
      case 'horizontal-bar':
        return <AlignHorizontalLeft fontSize="large" color="primary" />;
      case 'vertical-bar':
        return <ChartBar fontSize="large" color="primary" />;
      case 'donut':
        return <ChartDonut fontSize="large" color="primary" />;
      case 'area':
        return <ChartAreasplineVariant fontSize="large" color="primary" />;
      case 'timeline':
        return <ChartTimeline fontSize="large" color="primary" />;
      case 'list':
        return <ViewListOutline fontSize="large" color="primary" />;
      case 'distribution-list':
        return <FormatListNumberedRtl fontSize="large" color="primary" />;
      case 'number':
        return <Counter fontSize="large" color="primary" />;
      case 'text':
        return <FormatShapesOutlined fontSize="large" color="primary" />;
      case 'heatmap':
        return <ChartBubble fontSize="large" color="primary" />;
      case 'line':
        return <ChartLine fontSize="large" color="primary" />;
      case 'radar':
        return <Radar fontSize="large" color="primary" />;
      case 'tree':
        return <ChartTree fontSize="large" color="primary" />;
      case 'bookmark':
        return <StarSettingsOutline fontSize="large" color="primary" />;
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
          <Grid key={visualizationType.key} item={true} xs="4">
            <Card variant="outlined" className={classes.card3}>
              <CardActionArea
                onClick={() => handleSelectType(visualizationType.key)}
                style={{ height: '100%' }}
              >
                <CardContent>
                  {renderIcon(visualizationType.key)}
                  <Typography
                    gutterBottom
                    variant="body1"
                    style={{ marginTop: 8 }}
                  >
                    {t(visualizationType.name)}
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
              >
                <CardContent>
                  <DatabaseOutline style={{ fontSize: 40 }} color="primary" />
                  <Typography
                    gutterBottom
                    variant="h2"
                    style={{ marginTop: 20 }}
                  >
                    {t('Entities')}
                  </Typography>
                  <br />
                  <Typography variant="body1">
                    {t('Display global knowledge with filters and criteria.')}
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
              >
                <CardContent>
                  <FlaskOutline style={{ fontSize: 40 }} color="primary" />
                  <Typography
                    gutterBottom
                    variant="h2"
                    style={{ marginTop: 20 }}
                  >
                    {t('Knowledge graph')}
                  </Typography>
                  <br />
                  <Typography variant="body1">
                    {t(
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
                    {t('Activity & history')}
                  </Typography>
                  <br />
                  <Typography variant="body1">
                    {t('Display data related to the history and activity.')}
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
            let availableFilterKeys = entitiesFilters;
            let availableEntityTypes = [
              'Stix-Domain-Object',
              'Stix-Cyber-Observable',
            ];
            if (dataSelection[i].perspective === 'relationships') {
              style = 'step_relationship';
              availableFilterKeys = relationshipsFilters;
              availableEntityTypes = [
                'Stix-Domain-Object',
                'Stix-Cyber-Observable',
              ];
            } else if (dataSelection[i].perspective === 'audits') {
              style = 'step_audit';
              availableFilterKeys = auditsFilters;
              availableEntityTypes = ['History', 'Activity'];
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
                    label={`${t('Label')} (${dataSelection[i].perspective})`}
                    fullWidth={true}
                    value={dataSelection[i].label}
                    onChange={(event) => handleChangeDataValidationLabel(i, event.target.value)
                    }
                    InputProps={{
                      endAdornment: (
                        <InputAdornment
                          position="end"
                          style={{
                            position: 'absolute',
                            display: 'flex',
                            right: 5,
                          }}
                        >
                          <Filters
                            availableFilterKeys={availableFilterKeys}
                            availableEntityTypes={availableEntityTypes}
                            handleAddFilter={(key, id, value) => handleAddDataValidationFilter(i, key, id, value)
                            }
                            noDirectFilters={true}
                          />
                          {(dataSelection[i].perspective ?? perspective)
                            === 'relationships' && (
                            <Filters
                              availableFilterKeys={entitiesFilters}
                              availableEntityTypes={[
                                'Stix-Domain-Object',
                                'Stix-Cyber-Observable',
                              ]}
                              handleAddFilter={(key, id, value) => handleAddDataValidationDynamicFrom(
                                i,
                                key,
                                id,
                                value,
                              )
                              }
                              noDirectFilters={true}
                              type="from"
                            />
                          )}
                          {(dataSelection[i].perspective ?? perspective)
                            === 'relationships' && (
                            <Filters
                              availableFilterKeys={entitiesFilters}
                              availableEntityTypes={[
                                'Stix-Domain-Object',
                                'Stix-Cyber-Observable',
                              ]}
                              handleAddFilter={(key, id, value) => handleAddDataValidationDynamicTo(
                                i,
                                key,
                                id,
                                value,
                              )
                              }
                              noDirectFilters={true}
                              type="to"
                            />
                          )}
                        </InputAdornment>
                      ),
                    }}
                  />
                </div>
                <div className="clearfix" />
                <div className={classes.filters}>
                  {R.map((currentFilter) => {
                    const label = `${truncate(
                      t(`filter_${currentFilter[0]}`),
                      20,
                    )}`;
                    const localFilterMode = currentFilter[0].endsWith('not_eq')
                      ? t('AND')
                      : t('OR');
                    const values = (
                      <span>
                        {R.map(
                          (n) => (
                            <span key={n.value}>
                              {n.value && n.value.length > 0
                                ? truncate(n.value, 15)
                                : t('No label')}{' '}
                              {R.last(currentFilter[1]).value !== n.value && (
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
                          onDelete={() => handleRemoveDataSelectionFilter(i, currentFilter[0])
                          }
                        />
                        {R.last(R.toPairs(dataSelection[i].filters))[0]
                          !== currentFilter[0] && (
                          <Chip
                            classes={{ root: classes.operator }}
                            label={t('AND')}
                          />
                        )}
                      </span>
                    );
                  }, R.toPairs(dataSelection[i].filters))}
                  {R.map((currentFilter) => {
                    const label = `${truncate(
                      t(`filter_${currentFilter[0]}`),
                      20,
                    )}`;
                    const localFilterMode = currentFilter[0].endsWith('not_eq')
                      ? t('AND')
                      : t('OR');
                    const values = (
                      <span>
                        {R.map(
                          (n) => (
                            <span key={n.value}>
                              {n.value && n.value.length > 0
                                ? truncate(n.value, 15)
                                : t('No label')}{' '}
                              {R.last(currentFilter[1]).value !== n.value && (
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
                          color="warning"
                          classes={{ root: classes.filter }}
                          label={
                            <div>
                              <strong>{label}</strong>: {values}
                            </div>
                          }
                          onDelete={() => handleRemoveDataSelectionDynamicFrom(
                            i,
                            currentFilter[0],
                          )
                          }
                        />
                        {R.last(R.toPairs(dataSelection[i].dynamicFrom))[0]
                          !== currentFilter[0] && (
                          <Chip
                            classes={{ root: classes.operator }}
                            label={t('AND')}
                          />
                        )}
                      </span>
                    );
                  }, R.toPairs(dataSelection[i].dynamicFrom))}
                  {R.map((currentFilter) => {
                    const label = `${truncate(
                      t(`filter_${currentFilter[0]}`),
                      20,
                    )}`;
                    const localFilterMode = currentFilter[0].endsWith('not_eq')
                      ? t('AND')
                      : t('OR');
                    const values = (
                      <span>
                        {R.map(
                          (n) => (
                            <span key={n.value}>
                              {n.value && n.value.length > 0
                                ? truncate(n.value, 15)
                                : t('No label')}{' '}
                              {R.last(currentFilter[1]).value !== n.value && (
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
                          color="success"
                          classes={{ root: classes.filter }}
                          label={
                            <div>
                              <strong>{label}</strong>: {values}
                            </div>
                          }
                          onDelete={() => handleRemoveDataSelectionDynamicTo(
                            i,
                            currentFilter[0],
                          )
                          }
                        />
                        {R.last(R.toPairs(dataSelection[i].dynamicTo))[0]
                          !== currentFilter[0] && (
                          <Chip
                            classes={{ root: classes.operator }}
                            label={t('AND')}
                          />
                        )}
                      </span>
                    );
                  }, R.toPairs(dataSelection[i].dynamicTo))}
                </div>
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
              <AddOutlined fontSize="small" /> {t('Relationships')}
            </Button>
            <Button
              variant="contained"
              disabled={getCurrentDataSelectionLimit() === dataSelection.length}
              color="secondary"
              size="small"
              onClick={() => handleAddDataSelection('entities')}
              classes={{ root: classes.buttonAdd }}
            >
              <AddOutlined fontSize="small" /> {t('Entities')}
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
            {t('Validate')}
          </Button>
        </div>
      </div>
    );
  };
  const renderParameters = () => {
    return (
      <div style={{ marginTop: 20 }}>
        <TextField
          label={t('Title')}
          fullWidth={true}
          value={parameters.title}
          onChange={(event) => handleChangeParameter('title', event.target.value)
          }
        />
        {getCurrentCategory() === 'text' && (
          <div style={{ marginTop: 20 }}>
            <InputLabel shrink={true}>{t('Content')}</InputLabel>
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
              )
              }
              l18n={{
                write: t('Write'),
                preview: t('Preview'),
                uploadingImage: t('Uploading image'),
                pasteDropSelect: t('Paste'),
              }}
              minEditorHeight={100}
              maxEditorHeight={100}
            />
          </div>
        )}
        {getCurrentCategory() === 'timeseries' && (
          <FormControl fullWidth={true} style={{ marginTop: 20 }}>
            <InputLabel id="relative">{t('Interval')}</InputLabel>
            <Select
              labelId="relative"
              fullWidth={true}
              value={parameters.interval ?? 'day'}
              onChange={(event) => handleChangeParameter('interval', event.target.value)
              }
            >
              <MenuItem value="day">{t('Day')}</MenuItem>
              <MenuItem value="week">{t('Week')}</MenuItem>
              <MenuItem value="month">{t('Month')}</MenuItem>
              <MenuItem value="quarter">{t('Quarter')}</MenuItem>
              <MenuItem value="year">{t('Year')}</MenuItem>
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
                      label={t('Number of results')}
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
                            : t('Date attribute')}
                        </InputLabel>
                        <Select
                          labelId="relative"
                          size="small"
                          fullWidth={true}
                          value={
                            dataSelection[i].date_attribute ?? 'created_at'
                          }
                          onChange={(event) => handleChangeDataValidationParameter(
                            i,
                            'date_attribute',
                            event.target.value,
                          )
                          }
                        >
                          <MenuItem value="created_at">
                            created_at ({t('Technical date')})
                          </MenuItem>
                          <MenuItem value="updated_at">
                            updated_at ({t('Technical date')})
                          </MenuItem>
                          <MenuItem value="created">
                            created ({t('Functional date')})
                          </MenuItem>
                          <MenuItem value="modified">
                            modified ({t('Functional date')})
                          </MenuItem>
                          {getCurrentIsRelationships() && (
                            <MenuItem value="start_time">
                              start_time ({t('Functional date')})
                            </MenuItem>
                          )}
                          {getCurrentIsRelationships() && (
                            <MenuItem value="stop_time">
                              stop_time ({t('Functional date')})
                            </MenuItem>
                          )}
                          {getCurrentIsRelationships() && (
                            <MenuItem value="first_seen">
                              first_seen ({t('Functional date')})
                            </MenuItem>
                          )}
                          {getCurrentIsRelationships() && (
                            <MenuItem value="last_seen">
                              last_seen ({t('Functional date')})
                            </MenuItem>
                          )}
                        </Select>
                      </FormControl>
                    </div>
                  )}
                  {dataSelection[i].perspective === 'relationships'
                    && type === 'map' && (
                      <TextField
                        label={t('Zoom')}
                        fullWidth={true}
                        value={dataSelection[i].zoom ?? 2}
                        placeholder={t('Zoom')}
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
                        label={t('Center latitude')}
                        fullWidth={true}
                        value={dataSelection[i].centerLat ?? 48.8566969}
                        placeholder={t('Center latitude')}
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
                        label={t('Center longitude')}
                        fullWidth={true}
                        value={dataSelection[i].centerLng ?? 2.3514616}
                        placeholder={t('Center longitude')}
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
                          <InputLabel>{t('Attribute')}</InputLabel>
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
                              {t('Entity')}
                            </MenuItem>
                            <MenuItem key="entity_type" value="entity_type">
                              {t('Entity type')}
                            </MenuItem>
                            <MenuItem key="created-by.internal_id" value="created-by.internal_id">
                              {t('Author')}
                            </MenuItem>
                            <MenuItem key="object-marking.internal_id" value="object-marking.internal_id">
                              {t('Marking definition')}
                            </MenuItem>
                            <MenuItem key="kill-chain-phase.internal_id" value="kill-chain-phase.internal_id">
                              {t('Kill chain phase')}
                            </MenuItem>
                            <MenuItem key="creator_id" value="creator_id">
                              {t('Creator')}
                            </MenuItem>
                          </Select>
                        </FormControl>
                      )}
                      {dataSelection[i].perspective === 'entities'
                        && getCurrentSelectedEntityTypes(i).length > 0 && (
                          <FormControl
                            className={classes.formControl}
                            fullWidth={true}
                            style={{
                              flex: 1,
                            }}
                          >
                            <InputLabel>{t('Attribute')}</InputLabel>
                            <QueryRenderer
                              query={stixCyberObservablesLinesAttributesQuery}
                              variables={{
                                elementType: getCurrentSelectedEntityTypes(i),
                              }}
                              render={({ props: resultProps }) => {
                                if (
                                  resultProps
                                  && resultProps.schemaAttributes
                                ) {
                                  let attributes = R.pipe(
                                    R.map((n) => n.node),
                                    R.filter(
                                      (n) => !R.includes(
                                        n.value,
                                        ignoredAttributesInDashboards,
                                      ) && !n.value.startsWith('i_'),
                                    ),
                                  )(resultProps.schemaAttributes.edges);
                                  if (
                                    attributes.filter(
                                      (n) => n.value === 'hashes',
                                    ).length > 0
                                  ) {
                                    attributes = R.sortBy(
                                      R.prop('value'),
                                      [
                                        ...attributes,
                                        { value: 'hashes.MD5' },
                                        { value: 'hashes.SHA-1' },
                                        { value: 'hashes.SHA-256' },
                                        { value: 'hashes.SHA-512' },
                                      ].filter((n) => n.value !== 'hashes'),
                                    );
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
                                        ...attributes,
                                        { value: 'created-by.internal_id' },
                                        { value: 'object-label.internal_id' },
                                        {
                                          value: 'object-assignee.internal_id',
                                        },
                                        { value: 'object-marking.internal_id' },
                                        {
                                          value: 'kill-chain-phase.internal_id',
                                        },
                                      ].map((attribute) => (
                                        <MenuItem
                                          key={attribute.value}
                                          value={attribute.value}
                                        >
                                          {t(
                                            capitalizeFirstLetter(
                                              attribute.value,
                                            ),
                                          )}
                                        </MenuItem>
                                      ))}
                                    </Select>
                                  );
                                }
                                return <div />;
                              }}
                            />
                          </FormControl>
                      )}
                      {dataSelection[i].perspective === 'entities'
                        && getCurrentSelectedEntityTypes(i).length === 0 && (
                          <TextField
                            style={{
                              flex: 1,
                              marginRight:
                                dataSelection[i].perspective === 'relationships'
                                  ? 20
                                  : 0,
                            }}
                            label={t('Field')}
                            fullWidth={true}
                            value={dataSelection[i].attribute}
                            placeholder={t('Series attribute')}
                            onChange={(event) => handleChangeDataValidationParameter(
                              i,
                              'attribute',
                              event.target.value,
                            )
                            }
                          />
                      )}
                      {dataSelection[i].perspective === 'audits' && (
                        <FormControl
                          className={classes.formControl}
                          fullWidth={true}
                          style={{
                            flex: 1,
                          }}
                        >
                          <InputLabel>{t('Attribute')}</InputLabel>
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
                              { value: 'entity_type' },
                              { value: 'event_type' },
                              {
                                value: 'event_scope',
                              },
                              { value: 'context_data.id' },
                              {
                                value: 'user_id',
                              },
                              {
                                value: 'group_ids',
                              },
                              {
                                value: 'organization_ids',
                              },
                            ].map((attribute) => (
                              <MenuItem
                                key={attribute.value}
                                value={attribute.value}
                              >
                                {t(capitalizeFirstLetter(attribute.value))}
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
                          label={t('Display the source')}
                        />
                      )}
                      {dataSelection[i].perspective === 'relationships' && (
                        <Tooltip
                          title={t(
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
              label={t('Stacked')}
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
              label={t('Distributed')}
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
              label={t('Display legend')}
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
    <div>
      {!widget && (
        <Fab
          onClick={() => setOpen(true)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
      )}
      {widget && (
        <MenuItem
          onClick={() => {
            closeMenu();
            setOpen(true);
          }}
        >
          {t('Update')}
        </MenuItem>
      )}
      <Dialog
        open={open}
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        onClose={handleClose}
        fullWidth={true}
        maxWidth="md"
        className="noDrag"
      >
        <DialogTitle>
          <Stepper linear={false} activeStep={stepIndex}>
            <Step>
              <StepButton
                onClick={() => setStepIndex(0)}
                disabled={stepIndex === 0}
              >
                <StepLabel>{t('Visualization')}</StepLabel>
              </StepButton>
            </Step>
            <Step>
              <StepButton
                onClick={() => setStepIndex(1)}
                disabled={stepIndex <= 1 || getCurrentCategory() === 'text'}
              >
                <StepLabel>{t('Perspective')}</StepLabel>
              </StepButton>
            </Step>
            <Step>
              <StepButton
                onClick={() => setStepIndex(2)}
                disabled={stepIndex <= 2 || getCurrentCategory() === 'text'}
              >
                <StepLabel>{t('Filters')}</StepLabel>
              </StepButton>
            </Step>
            <Step>
              <StepButton
                onClick={() => setStepIndex(3)}
                disabled={stepIndex <= 3}
              >
                <StepLabel>{t('Parameters')}</StepLabel>
              </StepButton>
            </Step>
          </Stepper>
        </DialogTitle>
        <DialogContent>{getStepContent()}</DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>{t('Cancel')}</Button>
          <Button
            color="secondary"
            onClick={completeSetup}
            disabled={
              stepIndex !== 3
              || (getCurrentAvailableParameters().includes('attribute')
                && !isDataSelectionAttributesValid())
            }
          >
            {widget ? t('Update') : t('Create')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default WidgetConfig;
