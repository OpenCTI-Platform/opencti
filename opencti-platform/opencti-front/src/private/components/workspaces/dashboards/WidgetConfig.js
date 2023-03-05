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
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import Filters from '../../common/lists/Filters';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import { truncate } from '../../../../utils/String';
import { QueryRenderer } from '../../../../relay/environment';
import { stixCyberObservablesLinesAttributesQuery } from '../../observations/stix_cyber_observables/StixCyberObservablesLines';
import { ignoredAttributesInDashboards } from '../../../../utils/Entity';
import { isNotEmptyField } from '../../../../utils/utils';

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
  card2: {
    height: 100,
    backgroundColor: theme.palette.background.paperLight,
  },
  card3: {
    height: 100,
    backgroundColor: theme.palette.background.paperLight,
    textAlign: 'center',
  },
  dialog: {
    height: 600,
  },
  step_entity: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.secondary.main}`,
    borderRadius: 5,
  },
  step_relationship: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.primary.main}`,
    borderRadius: 5,
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
  'objectContains',
  'x_opencti_score',
  'x_opencti_detection',
  'revoked',
  'confidence',
  'pattern_type',
  'killChainPhase',
  'creator',
  'malware_types',
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

const visualizationTypes = [
  {
    key: 'number',
    name: 'Number',
    dataSelectionLimit: 1,
    category: 'number',
    availableParameters: [],
    isRelationships: true,
    isEntities: true,
  },
  {
    key: 'list',
    name: 'List',
    dataSelectionLimit: 1,
    category: 'timeseries',
    availableParameters: [],
    isRelationships: true,
    isEntities: true,
  },
  {
    key: 'vertical-bar',
    name: 'Vertical Bar',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: ['stacked', 'legend'],
    isRelationships: true,
    isEntities: true,
  },
  {
    key: 'line',
    name: 'Line',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: ['legend'],
    isRelationships: true,
    isEntities: true,
  },
  {
    key: 'area',
    name: 'Area',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: ['stacked', 'legend'],
    isRelationships: true,
    isEntities: true,
  },
  {
    key: 'timeline',
    name: 'Timeline',
    dataSelectionLimit: 1,
    category: 'timeline',
    availableParameters: [],
    isRelationships: true,
    isEntities: true,
  },
  {
    key: 'donut',
    name: 'Donut',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
  },
  {
    key: 'horizontal-bar',
    name: 'Horizontal Bar',
    dataSelectionLimit: 2,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
  },
  {
    key: 'radar',
    name: 'Radar',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: true,
  },
  {
    key: 'heatmap',
    name: 'Heatmap',
    dataSelectionLimit: 5,
    category: 'timeseries',
    availableParameters: ['stacked', 'legend'],
    isRelationships: true,
    isEntities: true,
  },
  {
    key: 'tree',
    name: 'Tree',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute', 'distributed'],
    isRelationships: true,
    isEntities: true,
  },
  {
    key: 'map',
    name: 'Map',
    dataSelectionLimit: 1,
    category: 'distribution',
    availableParameters: ['attribute'],
    isRelationships: true,
    isEntities: false,
  },
  {
    key: 'bookmark',
    name: 'Bookmark',
    dataSelectionLimit: 1,
    category: 'timeseries',
    availableParameters: [],
    isRelationships: false,
    isEntities: true,
  },
];
const indexedVisualizationTypes = R.indexBy(R.prop('key'), visualizationTypes);

const WidgetConfig = ({ widget, onComplete, closeMenu }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const [stepIndex, setStepIndex] = useState(widget?.dataSelection ? 2 : 0);
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
    setStepIndex(1);
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
  const handleChangeDataValidationParameter = (i, key, value) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return { ...dataSelection[i], [key]: value };
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
      case 'number':
        return <Counter fontSize="large" color="primary" />;
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
    const isEntitiesAndRelationships = getCurrentIsEntities() && getCurrentIsRelationships();
    return (
      <Grid
        container={true}
        spacing={3}
        style={{ marginTop: 20, marginBottom: 20 }}
      >
        {getCurrentIsEntities() && (
          <Grid item={true} xs={isEntitiesAndRelationships ? '6' : '12'}>
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
          <Grid item={true} xs={isEntitiesAndRelationships ? '6' : '12'}>
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
      </Grid>
    );
  };
  const renderDataSelection = () => {
    return (
      <div style={{ marginTop: 20 }}>
        {Array(dataSelection.length)
          .fill(0)
          .map((_, i) => {
            const style = dataSelection[i].perspective === 'entities'
              ? 'step_entity'
              : 'step_relationship';
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
                    variant="standard"
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
                            availableFilterKeys={
                              (dataSelection[i].perspective ?? perspective)
                              === 'entities'
                                ? entitiesFilters
                                : relationshipsFilters
                            }
                            availableEntityTypes={[
                              'Stix-Domain-Object',
                              'Stix-Cyber-Observable',
                            ]}
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
          variant="standard"
          label={t('Title')}
          fullWidth={true}
          value={parameters.title}
          onChange={(event) => handleChangeParameter('title', event.target.value)
          }
        />
        {getCurrentCategory() === 'timeseries' && (
          <FormControl
            fullWidth={true}
            variant="standard"
            style={{ marginTop: 20 }}
          >
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
        <div>
          {Array(dataSelection.length)
            .fill(0)
            .map((_, i) => {
              return (
                <div key={i} style={{ marginTop: 20 }}>
                  <div style={{ display: 'flex', width: '100%' }}>
                    <FormControl fullWidth={true} style={{ flex: 1 }}>
                      <InputLabel id="relative" variant="standard" size="small">
                        {isNotEmptyField(dataSelection[i].label)
                          ? dataSelection[i].label
                          : 'Unspecified'}
                      </InputLabel>
                      <Select
                        variant="standard"
                        labelId="relative"
                        size="small"
                        fullWidth={true}
                        value={dataSelection[i].date_attribute ?? 'created_at'}
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
                      </Select>
                    </FormControl>
                  </div>
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
                          <InputLabel variant="standard">
                            {t('Attribute')}
                          </InputLabel>
                          <Select
                            fullWidth={true}
                            variant="standard"
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
                            <InputLabel variant="standard">
                              {t('Attribute')}
                            </InputLabel>
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
                                      variant="standard"
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
                                        { value: 'object-marking.internal_id' },
                                        { value: 'object-marking.internal_id' },
                                        {
                                          value: 'kill-chain-phase.internal_id',
                                        },
                                      ].map((attribute) => (
                                        <MenuItem
                                          key={attribute.value}
                                          value={attribute.value}
                                        >
                                          {attribute.value}
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
                            variant="standard"
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
        </div>
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
                disabled={stepIndex <= 1}
              >
                <StepLabel>{t('Perspective')}</StepLabel>
              </StepButton>
            </Step>
            <Step>
              <StepButton
                onClick={() => setStepIndex(2)}
                disabled={stepIndex <= 2}
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
