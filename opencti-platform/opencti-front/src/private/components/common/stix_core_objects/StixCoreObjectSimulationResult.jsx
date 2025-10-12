import { Field, Form, Formik } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import React, { useState } from 'react';
import Tooltip from '@mui/material/Tooltip';
import { CheckOutlined, ErrorOutlined, LaunchOutlined, OpenInNewOutlined } from '@mui/icons-material';
import Box from '@mui/material/Box';
import CircularProgress from '@mui/material/CircularProgress';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import DialogTitle from '@mui/material/DialogTitle';
import * as Yup from 'yup';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import Avatar from '@mui/material/Avatar';
import Drawer from '../drawer/Drawer';
import Chart from '../charts/Chart';
import Transition from '../../../../components/Transition';
import obasLight from '../../../../static/images/xtm/obas_light.png';
import obasDark from '../../../../static/images/xtm/obas_dark.png';
import { donutChartOptions } from '../../../../utils/Charts';
import { fileUri } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SelectField from '../../../../components/fields/SelectField';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import { isEmptyField, isNotEmptyField } from '../../../../utils/utils';

const useStyles = makeStyles((theme) => ({
  simulationResults: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
  },
  charts: {
    display: 'flex',
  },
  chartContainer: {
    position: 'relative',
    overflow: 'hidden',
    width: 40,
    height: 40,
    padding: 4,
  },
  chart: {
    position: 'absolute',
    top: -5,
    left: -5,
  },
  iconOverlay: {
    fontSize: 18,
    position: 'absolute',
    top: 16,
    left: 16,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const StixCoreObjectSimulationResult = ({ id, coverage }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const theme = useTheme();
  const isGrantedToUpdate = useGranted([KNOWLEDGE_KNUPDATE]);
  const [helpers] = useFiltersState(emptyFilterGroup);

  const [open, setOpen] = useState(false);
  const [openCallToAction, setOpenCallToAction] = useState(false);
  const [platforms, setPlatforms] = useState([{ label: 'Windows', value: 'Windows' }]);
  const [architecture, setArchitecture] = useState('x86_64');
  const [selection, setSelection] = useState('random');
  const [interval, setInterval] = useState(2);
  const [result, setResult] = useState(null);
  const [resultError, setResultError] = useState(null);

  const platformOptions = [
    { label: 'Windows', value: 'Windows' },
    { label: 'Linux', value: 'Linux' },
    { label: 'MacOS', value: 'MacOS' },
  ];

  const handleClose = () => {
    setInterval(2);
    helpers.handleClearAllFilters();
    setOpen(false);
  };

  const handleCloseFinal = () => {
    setResult(null);
    setResultError(null);
    handleClose();
  };

  const initialValues = {
    platforms,
    architecture,
    interval,
    selection,
  };

  const simulationGenerationValidator = () => {
    const basicShape = {
      simulationType: Yup.string().required(t_i18n('This field is required')),
      interval: Yup.number().required(t_i18n('This field is required')).positive(t_i18n('Interval must be a positive number')).integer(t_i18n('Interval must be an integer')),
      selection: Yup.string().required(t_i18n('This field is required')),
    };
    // For technical type
    const technicalShape = {
      platforms: Yup.array().min(1, t_i18n('Minimum one platform')).required(t_i18n('This field is required')),
      architecture: Yup.string().required(t_i18n('This field is required')),
    };
    return Yup.object().shape({ ...basicShape, ...technicalShape });
  };

  const renderForm = () => {
    return (
      <Formik
        initialValues={initialValues}
        validationSchema={simulationGenerationValidator}
        onSubmit={() => { /* console.log('TODO change to create security coverage entity') */ }}
      >
        {({ values }) => (
          <Form id={id}>
            {values.simulationType !== 'simulated' && (
              <>
                {/*! hasAttackPatterns && (
                  <Alert severity="warning" variant="outlined" style={{ marginTop: 5 }}>
                    {t_i18n('Technical (payloads) requires attack patterns in this entity.')}
                  </Alert>
                ) */}
                <div style={fieldSpacingContainerStyle}>
                  <Field
                    component={AutocompleteField}
                    name="platforms"
                    textfieldprops={{
                      variant: 'standard',
                      label: t_i18n('Targeted platforms'),
                    }}
                    multiple
                    options={platformOptions}
                    onChange={(_event, newValue) => setPlatforms(newValue)}
                    renderOption={(props, option) => (
                      <li {...props}>
                        <div className={classes.text}>{option.label ?? ''}</div>
                      </li>
                    )}
                    disabled={false}
                  />
                </div>
                <div style={fieldSpacingContainerStyle}>
                  <Field
                    component={SelectField}
                    label={t_i18n('Targeted architecture')}
                    name="architecture"
                    fullWidth
                    disabled={false}
                    onChange={(_event, newValue) => setArchitecture(newValue)}
                    containerstyle={{ width: '100%' }}
                  >
                    <MenuItem value="x86_64">x86_64</MenuItem>
                    <MenuItem value="arm64">arm64</MenuItem>
                  </Field>
                </div>
              </>
            )}
            <div style={fieldSpacingContainerStyle}>
              <Field
                component={TextField}
                variant="standard"
                type="number"
                label={t_i18n('Interval between injections (in minutes)')}
                name="interval"
                fullWidth
                disabled={true}
                onChange={(_event, newValue) => setInterval(parseInt(newValue, 10))}
              />
            </div>
            <div style={fieldSpacingContainerStyle}>
              <Field
                component={SelectField}
                variant="standard"
                label={t_i18n('Number of injects generated by attack pattern and platform')}
                name="selection"
                fullWidth
                disabled={true}
                onChange={(_event, newValue) => setSelection(newValue)}
                containerstyle={{ width: '100%' }}
              >
                <MenuItem value="random">{t_i18n('One (random)')}</MenuItem>
                <MenuItem value="multiple">{t_i18n('Multiple (limited to 5)')}</MenuItem>
              </Field>
            </div>
            <div className={classes.buttons}>
              <Button
                variant="contained"
                onClick={handleClose}
                disabled={true}
                classes={{ root: classes.button }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                variant="contained"
                color="secondary"
                type="submit"
                disabled={true}
                classes={{ root: classes.button }}
              >
                {t_i18n('Generate')}
              </Button>
            </div>
          </Form>
        )}
      </Formik>
    );
  };

  const renderCharts = () => {
    return (
      <div className={classes.charts}>
        {(coverage?.coverage_information ?? []).map((coverageResult) => {
          let chartColors = [theme.palette.action.disabled];
          let labels = [t_i18n('Unknown')];
          let series = [coverageResult.coverage_score];
          if (isNotEmptyField(coverageResult.coverage_score)) {
            chartColors = [theme.palette.success.main, theme.palette.error.main];
            labels = [t_i18n('Success'), t_i18n('Failure')];
            series = [coverageResult.coverage_score, 100 - coverageResult.coverage_score];
          }
          const options = donutChartOptions(
            theme,
            labels,
            'bottom',
            false,
            chartColors,
            false,
            false,
            true,
            false,
            65,
            false,
          );
          return <div key={coverageResult.coverage_name} className={classes.chartContainer}>
            <div className={classes.chart}>
              <Chart options={options} series={series} type="donut" width={50} height={50}/>
              <Tooltip title={`${t_i18n(coverageResult.coverage_name)}`} placement="bottom">
                <Avatar className={classes.iconOverlay} sx={{ bgcolor: 'transparent', width: 18, height: 18 }}>
                  <span style={{ color: '#ffffff' }}>{coverageResult.coverage_name.charAt(0).toUpperCase()}</span>
                </Avatar>
              </Tooltip>
            </div>
          </div>;
        })}
      </div>
    );
  };

  const renderCooking = () => {
    return (
      <div style={{ margin: '0 auto', width: 200, height: 230 }}>
        <Box sx={{ position: 'relative', display: 'inline-flex' }}>
          <CircularProgress size={200} thickness={0.3} />
          <Box
            sx={{
              top: 0,
              left: 0,
              bottom: 0,
              right: 0,
              position: 'absolute',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Typography
              variant="caption"
              component="div"
              sx={{
                color: 'text.secondary',
              }}
            >
              {t_i18n('Scenario generation in progress...')}
            </Typography>
          </Box>
        </Box>
      </div>
    );
  };

  const renderResult = () => {
    return (
      <>
        <Alert icon={<CheckOutlined fontSize="inherit" />} severity="success">
          {t_i18n('The scenario has been correctly generated in your OpenBAS platform.')}
        </Alert>
        {result.attackPatternsNotAvailableInOpenBAS && result.attackPatternsNotAvailableInOpenBAS.trim() !== '' && (
          <Alert severity="warning" sx={{ marginTop: 2 }}>
            {t_i18n('The following TTPs are not covered in your OpenBAS catalog : ')}
            <ul
              style={{
                columnCount: Math.min(Math.ceil(result.attackPatternsNotAvailableInOpenBAS.split(',').length / 10), 20),
                paddingLeft: 20,
              }}
            >
              {result.attackPatternsNotAvailableInOpenBAS.split(',').map((ttp, index) => (
                <li key={index}>{ttp}</li>
              ))}
            </ul>
            {result.hasInjectPlaceholders && (
              <span>{t_i18n('In response, we have created placeholders for these TTPs.')}</span>
            )}
          </Alert>
        )}
        <Box style={{ marginTop: 20 }} sx={{ textAlign: 'center' }}>
          <Button component={Link} to={result.urlResponse} target="_blank" variant="outlined" endIcon={<OpenInNewOutlined />}>
            {t_i18n('Access this scenario')}
          </Button>
        </Box>
      </>
    );
  };

  const renderResultError = () => {
    return (
      <Alert icon={<ErrorOutlined fontSize="inherit" />} severity="error">
        {resultError}
      </Alert>
    );
  };

  return (
    <>
      <div className={classes.simulationResults}>
        {isEmptyField(coverage)
          ? <Tooltip title={`${t_i18n('Create a coverage')}`}>
            <Button
              variant="outlined"
              size="small"
              style={{ fontSize: 12 }}
              disabled={!isGrantedToUpdate}
              onClick={() => setOpen(true)}
            >
              <img style={{ width: 20, height: 20, marginRight: 5, display: 'block' }} src={fileUri(theme.palette.mode === 'dark' ? obasDark : obasLight)} alt="OAEV" />
              {t_i18n('Add Security coverage')}
            </Button>
          </Tooltip> : <div>LINK</div>}
        {renderCharts()}
      </div>
      <Drawer
        title={t_i18n('Generate a simulation scenario')}
        open={open}
        onClose={handleClose}
      >
        {renderForm()}
      </Drawer>
      <Dialog
        open={!!(result || resultError)}
        slotProps={{ paper: { elevation: 1 } }}
        slots={{ transition: Transition }}
        onClose={handleCloseFinal}
        maxWidth="xs"
        fullWidth={true}
      >
        <DialogContent>
          {renderCooking()}
          {result && renderResult()}
          {resultError && renderResultError()}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseFinal} disabled={true}>{t_i18n('Close')}</Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={openCallToAction}
        slotProps={{ paper: { elevation: 1 } }}
        slots={{ transition: Transition }}
        onClose={() => setOpenCallToAction(false)}
        maxWidth="md"
        fullWidth={true}
      >
        <DialogTitle>{t_i18n('Install the OpenBAS platform')}</DialogTitle>
        <DialogContent>
          <p>{t_i18n('You are trying to check the security posture of your organization against this threat intelligence set of knowledge using the OpenBAS platform.')}</p>
          <p>{t_i18n('To be able to generate a scenario, whether technical or strategic, you need a working OpenBAS installation. Alternatively, your administrator can completely disable the integration in the parameters of this platform.')}</p>
          <Button
            variant="text"
            endIcon={<LaunchOutlined />}
            component="a"
            href="https://docs.openbas.io/latest/deployment/installation/"
            target="_blank"
          >
            {t_i18n('OpenBAS installation documentation')}
          </Button>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenCallToAction(false)}>{t_i18n('Close')}</Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default StixCoreObjectSimulationResult;
