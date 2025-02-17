import { Field, Form, Formik } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import React, { useState } from 'react';
import Tooltip from '@mui/material/Tooltip';
import { CheckOutlined, ErrorOutlined, LaunchOutlined, OpenInNewOutlined, SensorOccupiedOutlined, ShieldOutlined, TrackChangesOutlined } from '@mui/icons-material';
import Box from '@mui/material/Box';
import CircularProgress from '@mui/material/CircularProgress';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import DialogTitle from '@mui/material/DialogTitle';
import { graphql, usePreloadedQuery } from 'react-relay';
import * as Yup from 'yup';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '../drawer/Drawer';
import Chart from '../charts/Chart';
import EEChip from '../entreprise_edition/EEChip';
import Transition from '../../../../components/Transition';
import obasLight from '../../../../static/images/xtm/obas_light.png';
import obasDark from '../../../../static/images/xtm/obas_dark.png';
import { donutChartOptions } from '../../../../utils/Charts';
import { extractSimpleError, fileUri, QueryRenderer } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SelectField from '../../../../components/fields/SelectField';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import useXTM from '../../../../utils/hooks/useXTM';
import useAI from '../../../../utils/hooks/useAI';

const stixCoreObjectSimulationResultObasStixCoreObjectSimulationsResultQuery = graphql`
  query StixCoreObjectSimulationResultObasStixCoreObjectSimulationsResultQuery($id: ID!) {
    obasStixCoreObjectSimulationsResult(id: $id) {
      prevention {
        unknown
        success
        failure
      }
      detection {
        unknown
        success
        failure
      }
      human {
        unknown
        success
        failure
      }
    }
  }
`;

const stixCoreObjectSimulationResultObasContainerGenerateScenarioWithInjectPlaceholdersMutation = graphql`
  mutation StixCoreObjectSimulationResultObasContainerGenerateScenarioWithInjectPlaceholdersMutation($id: ID!, $simulationConfig: SimulationConfig, $filters: FilterGroup) {
    obasContainerGenerateScenarioWithInjectPlaceholders(id: $id, simulationConfig: $simulationConfig, filters: $filters){
      urlResponse
      attackPatternsNotAvailableInOpenBAS
      hasInjectPlaceholders
    }
  }
`;

const stixCoreObjectSimulationResultObasThreatGenerateScenarioWithInjectPlaceholdersMutation = graphql`
  mutation StixCoreObjectSimulationResultObasThreatGenerateScenarioWithInjectPlaceholdersMutation($id: ID!, $simulationConfig: SimulationConfig, $filters: FilterGroup) {
    obasThreatGenerateScenarioWithInjectPlaceholders(id: $id, simulationConfig: $simulationConfig, filters: $filters) {
      urlResponse
      attackPatternsNotAvailableInOpenBAS
      hasInjectPlaceholders
    }
  }
`;

const stixCoreObjectSimulationResultObasVictimGenerateScenarioWithInjectPlaceholdersMutation = graphql`
  mutation StixCoreObjectSimulationResultObasVictimGenerateScenarioWithInjectPlaceholdersMutation($id: ID!, $simulationConfig: SimulationConfig, $filters: FilterGroup) {
    obasVictimGenerateScenarioWithInjectPlaceholders(id: $id, simulationConfig: $simulationConfig, filters: $filters){
      urlResponse
      attackPatternsNotAvailableInOpenBAS
      hasInjectPlaceholders
    }
  }
`;

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

const StixCoreObjectSimulationResult = ({
  id,
  queryRef,
  query,
  type,
  simulationType,
  setSimulationType,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const theme = useTheme();
  const isEnterpriseEdition = useEnterpriseEdition();
  const isGrantedToUpdate = useGranted([KNOWLEDGE_KNUPDATE]);
  const { enabled, configured } = useAI();
  const isSimulatedEmailsAvailable = enabled && configured && isEnterpriseEdition;

  const { oBasConfigured, oBasDisableDisplay } = useXTM();
  const [filters, helpers] = useFiltersState(emptyFilterGroup);

  const [open, setOpen] = useState(false);
  const [openCallToAction, setOpenCallToAction] = useState(false);
  const [platforms, setPlatforms] = useState([{ label: 'Windows', value: 'Windows' }]);
  const [architecture, setArchitecture] = useState('x86_64');
  const [selection, setSelection] = useState('random');
  const [interval, setInterval] = useState(2);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [result, setResult] = useState(null);
  const [resultError, setResultError] = useState(null);
  const draftContext = useDraftContext();
  const disabledInDraft = !!draftContext;

  const attackPatterns = usePreloadedQuery(query, queryRef);

  // Check if there are attack patterns in the entity
  const hasAttackPatterns = (
    (type === 'container' && attackPatterns?.stixCoreObject?.objects?.edges?.length > 0)
    || (type === 'threat' && attackPatterns?.stixCoreRelationships?.edges?.length > 0)
  );

  const platformOptions = [
    { label: 'Windows', value: 'Windows' },
    { label: 'Linux', value: 'Linux' },
    { label: 'MacOS', value: 'MacOS' },
  ];

  const opacity = (!hasAttackPatterns && simulationType) === 'technical' ? 0.38 : 1;

  const handleClose = () => {
    setSimulationType('technical');
    setInterval(2);
    helpers.handleClearAllFilters();
    setOpen(false);
  };

  const handleCloseFinal = () => {
    setResult(null);
    setResultError(null);
    handleClose();
  };

  const canGenerateScenario = () => {
    return (
      (simulationType === 'technical' && hasAttackPatterns && platforms.length > 0 && architecture)
      || (simulationType === 'simulated' && enabled && configured && isEnterpriseEdition)
      || (simulationType === 'mixed' && ((enabled && configured && isEnterpriseEdition) && (hasAttackPatterns && platforms.length > 0 && architecture)))
    );
  };

  const [commitMutationGenerateContainer] = useApiMutation(stixCoreObjectSimulationResultObasContainerGenerateScenarioWithInjectPlaceholdersMutation);
  const [commitMutationGenerateThreat] = useApiMutation(stixCoreObjectSimulationResultObasThreatGenerateScenarioWithInjectPlaceholdersMutation);
  const [commitMutationGenerateVictim] = useApiMutation(stixCoreObjectSimulationResultObasVictimGenerateScenarioWithInjectPlaceholdersMutation);

  const handleGenerate = () => {
    setIsSubmitting(true);
    setOpen(false);
    const selectedPlatforms = platforms.map((option) => option.value);
    switch (type) {
      case 'container':
        commitMutationGenerateContainer({
          variables: {
            id,
            simulationConfig: {
              interval,
              selection,
              simulationType,
              platforms: selectedPlatforms,
              architecture,
            },
            filters,
          },
          onCompleted: (response) => {
            setResult(response.obasContainerGenerateScenarioWithInjectPlaceholders);
            setIsSubmitting(false);
            handleClose();
          },
          onError: (error) => {
            setResultError(extractSimpleError(error));
            setIsSubmitting(false);
            handleClose();
          },
        });
        break;
      case 'threat':
        commitMutationGenerateThreat({
          variables: {
            id,
            simulationConfig: {
              interval,
              selection,
              simulationType,
              platforms: selectedPlatforms,
              architecture,
            },
            filters,
          },
          onCompleted: (response) => {
            setResult(response.obasThreatGenerateScenarioWithInjectPlaceholders);
            setIsSubmitting(false);
            handleClose();
          },
          onError: (error) => {
            setResultError(extractSimpleError(error));
            setIsSubmitting(false);
            handleClose();
          },
        });
        break;
      case 'victim':
        commitMutationGenerateVictim({
          variables: {
            id,
            simulationConfig: {
              interval,
              selection,
              simulationType,
              platforms: selectedPlatforms,
              architecture,
            },
            filters,
          },
          onCompleted: (response) => {
            setResult(response.obasVictimGenerateScenarioWithInjectPlaceholders);
            setIsSubmitting(false);
            handleClose();
          },
          onError: (error) => {
            setResultError(extractSimpleError(error));
            setIsSubmitting(false);
            handleClose();
          },
        });
        break;
      default:
      // do nothing
    }
  };

  const initialValues = {
    simulationType,
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
    if (simulationType === 'simulated') {
      return Yup.object().shape({
        ...basicShape,
      });
    }
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
        onSubmit={handleGenerate}
      >
        {({ isValid, values }) => (
          <Form>
            <div style={{ width: '100%' }}>
              <Field
                component={SelectField}
                variant="standard"
                name="simulationType"
                label={t_i18n('Simulation type')}
                fullWidth
                onChange={(_event, newValue) => setSimulationType(newValue)}
                containerstyle={{ width: '100%', marginTop: 20, opacity }}
              >
                <MenuItem value="technical">
                  {t_i18n('Technical (payloads)')}
                </MenuItem>
                <MenuItem value="simulated" disabled={!isSimulatedEmailsAvailable}>
                  {t_i18n('Simulated emails (generated by AI)')} <EEChip />
                </MenuItem>
                <MenuItem value="mixed" disabled>
                  {t_i18n('Mixed (both)')} <EEChip />
                </MenuItem>
              </Field>
            </div>
            {values.simulationType !== 'simulated' && (
              <>
                {!hasAttackPatterns && (
                  <Alert severity="warning" variant="outlined" style={{ marginTop: 5 }}>
                    {t_i18n('Technical (payloads) requires attack patterns in this entity.')}
                  </Alert>
                )}
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
                    disabled={!hasAttackPatterns}
                  />
                </div>
                <div style={fieldSpacingContainerStyle}>
                  <Field
                    component={SelectField}
                    label={t_i18n('Targeted architecture')}
                    name="architecture"
                    fullWidth
                    disabled={!hasAttackPatterns}
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
                disabled={!canGenerateScenario()}
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
                disabled={!canGenerateScenario()}
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
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                variant="contained"
                color="secondary"
                type="submit"
                disabled={isSubmitting || !canGenerateScenario() || !isValid}
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
      <QueryRenderer
        query={stixCoreObjectSimulationResultObasStixCoreObjectSimulationsResultQuery}
        variables={{ id }}
        render={({ props }) => {
          const labels = [t_i18n('Unknown'), t_i18n('Success'), t_i18n('Failure')];
          const chartColors = [theme.palette.action.disabled, theme.palette.success.main, theme.palette.error.main];
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
          if (props && props.obasStixCoreObjectSimulationsResult) {
            const { prevention, detection, human } = props.obasStixCoreObjectSimulationsResult;
            return (
              <div className={classes.charts}>
                <div className={classes.chartContainer}>
                  <div className={classes.chart}>
                    <Chart
                      options={options}
                      series={[prevention.unknown, prevention.success, prevention.failure]}
                      type="donut"
                      width={50}
                      height={50}
                    />
                    <Tooltip title={`${t_i18n('Prevention')}`} placement="bottom">
                      <ShieldOutlined className={classes.iconOverlay} />
                    </Tooltip>
                  </div>
                </div>
                <div className={classes.chartContainer}>
                  <div className={classes.chart}>
                    <Chart
                      options={options}
                      series={[detection.unknown, detection.success, detection.failure]}
                      type="donut"
                      width={50}
                      height={50}
                    />
                    <Tooltip title={`${t_i18n('Detection')}`} placement="bottom">
                      <TrackChangesOutlined className={classes.iconOverlay} />
                    </Tooltip>
                  </div>
                </div>
                <div className={classes.chartContainer}>
                  <div className={classes.chart}>
                    <Chart
                      options={options}
                      series={[human.unknown, human.success, human.failure]}
                      type="donut"
                      width={50}
                      height={50}
                    />
                    <Tooltip title={`${t_i18n('Human response')}`} placement="bottom">
                      <SensorOccupiedOutlined className={classes.iconOverlay} />
                    </Tooltip>
                  </div>
                </div>
              </div>
            );
          }
          const chartData = [100];
          return (
            <div className={classes.charts}>
              <div className={classes.chartContainer}>
                <div className={classes.chart}>
                  <Chart
                    options={options}
                    series={chartData}
                    type="donut"
                    width={50}
                    height={50}
                  />
                  <Tooltip title={`${t_i18n('Prevention')}`} placement="bottom">
                    <ShieldOutlined className={classes.iconOverlay} />
                  </Tooltip>
                </div>
              </div>
              <div className={classes.chartContainer}>
                <div className={classes.chart}>
                  <Chart
                    options={options}
                    series={chartData}
                    type="donut"
                    width={50}
                    height={50}
                  />
                  <Tooltip title={`${t_i18n('Detection')}`} placement="bottom">
                    <TrackChangesOutlined className={classes.iconOverlay} />
                  </Tooltip>
                </div>
              </div>
              <div className={classes.chartContainer}>
                <div className={classes.chart}>
                  <Chart
                    options={options}
                    series={chartData}
                    type="donut"
                    width={50}
                    height={50}
                  />
                  <Tooltip title={`${t_i18n('Human response')}`} placement="bottom">
                    <SensorOccupiedOutlined className={classes.iconOverlay} />
                  </Tooltip>
                </div>
              </div>
            </div>
          );
        }}
      />
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
              color="text.secondary"
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
        <Box textAlign="center" style={{ marginTop: 20 }}>
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
      {!oBasDisableDisplay && !disabledInDraft && (
        <div className={classes.simulationResults}>
          <Tooltip title={`${t_i18n('Check the posture in OpenBAS')}`}>
            <Button
              variant="outlined"
              size="small"
              style={{ fontSize: 12 }}
              disabled={!isGrantedToUpdate && oBasConfigured}
              onClick={() => (oBasConfigured ? setOpen(true) : setOpenCallToAction(true))}
            >
              <img style={{ width: 20, height: 20, marginRight: 5, display: 'block' }} src={fileUri(theme.palette.mode === 'dark' ? obasDark : obasLight)} alt="OBAS" />
              {t_i18n('Simulate')}
            </Button>
          </Tooltip>
          {renderCharts()}
        </div>
      )}
      <Drawer
        title={t_i18n('Generate a simulation scenario')}
        open={open}
        onClose={handleClose}
      >
        {renderForm()}
      </Drawer>
      <Dialog
        open={!!(isSubmitting || result || resultError)}
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        onClose={handleCloseFinal}
        maxWidth="xs"
        fullWidth={true}
      >
        <DialogContent>
          {isSubmitting && renderCooking()}
          {!isSubmitting && result && renderResult()}
          {!isSubmitting && resultError && renderResultError()}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseFinal} disabled={isSubmitting}>{t_i18n('Close')}</Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={openCallToAction}
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
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
