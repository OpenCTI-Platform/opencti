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
  ChartTimeline,
  ChartAreasplineVariant,
  ChartBar,
  ChartDonut,
  ChartBubble,
  AlignHorizontalLeft,
  ViewListOutline,
  Counter,
  DatabaseOutline,
  FlaskOutline,
} from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import TextField from '@mui/material/TextField';
import Chip from '@mui/material/Chip';
import MenuItem from '@mui/material/MenuItem';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import Filters, { isUniqFilter } from '../../common/lists/Filters';
import { truncate } from '../../../../utils/String';

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
  step: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.background.accent}`,
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
  buttonAdd: {
    width: '100%',
    height: 20,
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

const visualizationTypes = [
  { key: 'number', name: 'Number', dataSelectionLimit: 1, hasAttribute: false },
  { key: 'list', name: 'List', dataSelectionLimit: 1, hasAttribute: false },
  {
    key: 'vertical-bar',
    name: 'Vertical Bar',
    dataSelectionLimit: 2,
    hasAttribute: false,
  },
  { key: 'area', name: 'Area', dataSelectionLimit: 2, hasAttribute: false },
  { key: 'donut', name: 'Donut', dataSelectionLimit: 1, hasAttribute: true },
  {
    key: 'horizontal-bar',
    name: 'Horizontal Bar',
    dataSelectionLimit: 1,
    hasAttribute: true,
  },
  {
    key: 'timeline',
    name: 'Timeline',
    dataSelectionLimit: 1,
    hasAttribute: false,
  },
  {
    key: 'heatmap',
    name: 'Heatmap',
    dataSelectionLimit: 1,
    hasAttribute: false,
  },
  { key: 'map', name: 'Map', dataSelectionLimit: 1, hasAttribute: false },
];
const indexedVisualizationTypes = R.indexBy(R.prop('key'), visualizationTypes);

const WidgetConfig = ({ widget, onComplete, closeMenu }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const [stepIndex, setStepIndex] = useState(widget ? 2 : 0);
  const [type, setType] = useState(widget?.type ?? null);
  const [perspective, setPerspective] = useState(widget?.perspective ?? null);
  const [dataSelection, setDataSelection] = useState(
    widget?.dataSelection ?? [
      { label: '', attribute: '', isTo: false, filters: {} },
    ],
  );
  const handleClose = () => {
    if (!widget) {
      setStepIndex(0);
      setType(null);
      setPerspective(null);
      setDataSelection([
        { label: '', attribute: '', isTo: false, filters: {} },
      ]);
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
    });
    handleClose();
  };
  const getCurrentDataSelectionLimit = () => {
    return indexedVisualizationTypes[type]?.dataSelectionLimit ?? 0;
  };
  const getCurrentHasAttribute = () => {
    return indexedVisualizationTypes[type]?.hasAttribute ?? true;
  };
  const handleSelectType = (selectedType) => {
    setType(selectedType);
    setStepIndex(1);
  };
  const handleSelectPerspective = (selectedPerspective) => {
    setPerspective(selectedPerspective);
    setStepIndex(2);
  };
  const handleAddDataSelection = () => {
    setDataSelection([
      ...dataSelection,
      { label: '', attribute: '', filters: {} },
    ]);
  };
  const handleRemoveDataSelection = (i) => {
    setDataSelection(dataSelection.splice(i, 1));
  };
  const isDataSelectionFiltersValid = () => {
    for (const n of dataSelection) {
      if (n.label.length === 0) {
        return false;
      }
    }
    return true;
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
  const handleChangeDataValidationAttribute = (i, value) => {
    const newDataSelection = dataSelection.map((data, n) => {
      if (n === i) {
        return { ...dataSelection[i], attribute: value };
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
    return (
      <Grid
        container={true}
        spacing={3}
        style={{ marginTop: 20, marginBottom: 20 }}
      >
        <Grid item={true} xs="6">
          <Card variant="outlined" className={classes.card}>
            <CardActionArea
              onClick={() => handleSelectPerspective('entity')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <DatabaseOutline style={{ fontSize: 40 }} color="primary" />
                <Typography gutterBottom variant="h2" style={{ marginTop: 20 }}>
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
        <Grid item={true} xs="6">
          <Card variant="outlined" className={classes.card}>
            <CardActionArea
              onClick={() => handleSelectPerspective('relationship')}
              style={{ height: '100%' }}
            >
              <CardContent>
                <FlaskOutline style={{ fontSize: 40 }} color="primary" />
                <Typography gutterBottom variant="h2" style={{ marginTop: 20 }}>
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
      </Grid>
    );
  };
  const renderDataSelection = () => {
    return (
      <div style={{ marginTop: 20 }}>
        {Array(dataSelection.length)
          .fill(0)
          .map((_, i) => (
            <div key={i} className={classes.step}>
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
                  label={t('Label')}
                  fullWidth={true}
                  value={dataSelection[i].label}
                  onChange={(event) => handleChangeDataValidationLabel(i, event.target.value)
                  }
                  InputProps={{
                    endAdornment: (
                      <InputAdornment
                        position="end"
                        style={{ position: 'absolute', right: 5 }}
                      >
                        <Filters
                          availableFilterKeys={[
                            'markedBy',
                            'labelledBy',
                            'createdBy',
                            'x_opencti_score',
                            'x_opencti_detection',
                            'revoked',
                            'confidence',
                            'pattern_type',
                          ]}
                          handleAddFilter={(key, id, value) => handleAddDataValidationFilter(i, key, id, value)
                          }
                          noDirectFilters={true}
                        />
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
                  const values = (
                    <span>
                      {R.map(
                        (n) => (
                          <span key={n.value}>
                            {n.value && n.value.length > 0
                              ? truncate(n.value, 15)
                              : t('No label')}{' '}
                            {R.last(currentFilter[1]).value !== n.value && (
                              <code>OR</code>
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
              </div>
            </div>
          ))}
        <div className={classes.add}>
          <Button
            variant="contained"
            disabled={
              !isDataSelectionFiltersValid()
              || getCurrentDataSelectionLimit() === dataSelection.length
            }
            color="secondary"
            size="small"
            onClick={handleAddDataSelection}
            classes={{ root: classes.buttonAdd }}
          >
            <AddOutlined fontSize="small" />
          </Button>
        </div>
        {getCurrentHasAttribute() && (
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
        )}
      </div>
    );
  };
  const renderAttributes = () => {
    return (
      <div style={{ marginTop: 20 }}>
        {Array(dataSelection.length)
          .fill(0)
          .map((_, i) => (
            <div key={i} className={classes.step}>
              <div style={{ display: 'flex', width: '100%' }}>
                <TextField
                  style={{ flex: 1 }}
                  variant="standard"
                  label={dataSelection[i].label}
                  fullWidth={true}
                  value={dataSelection[i].attribute}
                  placeholder={t('Series attribute')}
                  onChange={(event) => handleChangeDataValidationAttribute(i, event.target.value)
                  }
                />
                <FormControlLabel
                  control={
                    <Switch
                      onChange={() => handleToggleDataValidationIsTo(i)}
                      checked={dataSelection[i].isTo}
                    />
                  }
                  label={t('In relationship target')}
                />
              </div>
            </div>
          ))}
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
        return renderAttributes();
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
                <StepLabel>{t('Attribute')}</StepLabel>
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
              !isDataSelectionFiltersValid()
              || (getCurrentHasAttribute()
                && (!isDataSelectionAttributesValid() || stepIndex !== 3))
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
