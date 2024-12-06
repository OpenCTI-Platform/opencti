import React, { useState } from 'react';
import { makeStyles, useTheme } from '@mui/styles';
import { CheckOutlined, OpenInNewOutlined, SensorOccupiedOutlined, ShieldOutlined, TrackChangesOutlined, ErrorOutlined, LaunchOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import Button from '@mui/material/Button';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import TextField from '@mui/material/TextField';
import Box from '@mui/material/Box';
import { graphql } from 'react-relay';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import CircularProgress from '@mui/material/CircularProgress';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';
import Alert from '@mui/material/Alert';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { Autocomplete } from '@mui/material';
import Drawer from '../drawer/Drawer';
import Chart from '../charts/Chart';
import { useFormatter } from '../../../../components/i18n';
import { donutChartOptions } from '../../../../utils/Charts';
import { extractSimpleError, fileUri, QueryRenderer } from '../../../../relay/environment';
import obasDark from '../../../../static/images/xtm/obas_dark.png';
import obasLight from '../../../../static/images/xtm/obas_light.png';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useAI from '../../../../utils/hooks/useAI';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';
import useXTM from '../../../../utils/hooks/useXTM';

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

const stixCoreObjectSimulationResultObasContainerGenerateScenarioMutation = graphql`
  mutation StixCoreObjectSimulationResultObasContainerGenerateScenarioMutation($id: ID!, $interval: Int, $selection: Selection, $simulationType: SimulationType, $simulationPlatforms: [SimulationPlatform], $simulationArchitecture: SimulationArchitecture, $useAI: Boolean, $filters: FilterGroup) {
    obasContainerGenerateScenario(id: $id, interval: $interval, selection: $selection, simulationType: $simulationType, simulationPlatforms: $simulationPlatforms, simulationArchitecture: $simulationArchitecture, useAI: $useAI, filters: $filters)
  }
`;

const stixCoreObjectSimulationResultObasThreatGenerateScenarioMutation = graphql`
  mutation StixCoreObjectSimulationResultObasThreatGenerateScenarioMutation($id: ID!, $interval: Int, $selection: Selection, $simulationType: SimulationType, $simulationPlatforms: [SimulationPlatform], $simulationArchitecture: SimulationArchitecture, $useAI: Boolean, $filters: FilterGroup) {
    obasThreatGenerateScenario(id: $id, interval: $interval, selection: $selection, simulationType: $simulationType, simulationPlatforms: $simulationPlatforms, simulationArchitecture: $simulationArchitecture, useAI: $useAI, filters: $filters)
  }
`;

const stixCoreObjectSimulationResultObasVictimGenerateScenarioMutation = graphql`
  mutation StixCoreObjectSimulationResultObasVictimGenerateScenarioMutation($id: ID!, $interval: Int, $selection: Selection, $simulationType: SimulationType, $simulationPlatforms: [SimulationPlatform], $simulationArchitecture: SimulationArchitecture, $useAI: Boolean, $filters: FilterGroup) {
    obasVictimGenerateScenario(id: $id, interval: $interval, selection: $selection, simulationType: $simulationType, simulationPlatforms: $simulationPlatforms, simulationArchitecture: $simulationArchitecture, useAI: $useAI, filters: $filters)
  }
`;

const platforms = [
  { label: 'Windows', value: 'Windows' },
  { label: 'Linux', value: 'Linux' },
  { label: 'MacOS', value: 'MacOS' },
];

const StixCoreObjectSimulationResult = ({ id, type }) => {
  const theme = useTheme();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const [openCallToAction, setOpenCallToAction] = useState(false);
  const isEnterpriseEdition = useEnterpriseEdition();
  const { configured } = useAI();
  const { oBasConfigured, oBasDisableDisplay } = useXTM();
  const [simulationType, setSimulationType] = useState('technical');
  const [simulationPlatforms, setSimulationPlatforms] = useState(['windows']);
  const [simulationArchitecture, setSimulationArchitecture] = useState('AMD64');
  const [selection, setSelection] = useState('random');
  const [interval, setInterval] = useState(2);
  const [useGenAI, setUseGenAI] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [result, setResult] = useState(null);
  const [resultError, setResultError] = useState(null);
  const [filters, helpers] = useFiltersState(emptyFilterGroup);
  const { t_i18n } = useFormatter();
  const isGrantedToUpdate = useGranted([KNOWLEDGE_KNUPDATE]);
  const hasAttackPatterns = true;

  const isFormValid = () => {
    return (
      (
        (simulationType === 'technical' && hasAttackPatterns)
        || (simulationType === 'simulated' && configured && isEnterpriseEdition)
        || (simulationType === 'mixed' && ((configured && isEnterpriseEdition) || hasAttackPatterns))
      )
      && simulationPlatforms.length > 0
      && simulationArchitecture
    );
  };

  const handleClose = () => {
    setSimulationType('technical');
    setInterval(2);
    setUseGenAI(false);
    helpers.handleClearAllFilters();
    setOpen(false);
  };

  const handleCloseFinal = () => {
    setResult(null);
    setResultError(null);
    handleClose();
  };

  const [commitMutationGenerateContainer] = useApiMutation(stixCoreObjectSimulationResultObasContainerGenerateScenarioMutation);
  const [commitMutationGenerateThreat] = useApiMutation(stixCoreObjectSimulationResultObasThreatGenerateScenarioMutation);
  const [commitMutationGenerateVictim] = useApiMutation(stixCoreObjectSimulationResultObasVictimGenerateScenarioMutation);

  const handleGenerate = () => {
    setIsSubmitting(true);
    setOpen(false);
    switch (type) {
      case 'container':
        commitMutationGenerateContainer({
          variables: {
            id,
            interval,
            selection,
            simulationType,
            simulationPlatforms,
            simulationArchitecture,
            useAI: useGenAI,
            filters,
          },
          onCompleted: (response) => {
            setResult(response.obasContainerGenerateScenario);
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
            interval,
            selection,
            simulationType,
            simulationPlatforms,
            simulationArchitecture,
            useAI: useGenAI,
            filters,
          },
          onCompleted: (response) => {
            setResult(response.obasThreatGenerateScenario);
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
            interval,
            selection,
            simulationType,
            simulationPlatforms,
            simulationArchitecture,
            useAI: useGenAI,
            filters,
          },
          onCompleted: (response) => {
            setResult(response.obasVictimGenerateScenario);
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
  const renderForm = () => {
    return (
      <>
        {!hasAttackPatterns && (
          <Alert
            severity="warning"
            variant="outlined"
            style={{ position: 'relative' }}
          >
            {t_i18n('No entity-type attack patterns were found.')}
          </Alert>
        )}
        <FormControl style={fieldSpacingContainerStyle}>
          <InputLabel id="simulationType">{t_i18n('Simulation type')}</InputLabel>
          <Select
            labelId="simulationType"
            value={simulationType}
            onChange={(event) => setSimulationType(event.target.value)}
            fullWidth
          >
            <MenuItem value="technical" disabled={ !hasAttackPatterns}>{t_i18n('Technical (payloads)')}</MenuItem>
            <MenuItem value="simulated" disabled={ !configured || !isEnterpriseEdition}>{t_i18n('Simulated emails (generated by AI) ')}{!isEnterpriseEdition && <EEChip />}</MenuItem>
            <MenuItem value="mixed" disabled>{t_i18n('Mixed (both) ')}{!isEnterpriseEdition && <EEChip />}</MenuItem>
          </Select>
        </FormControl>
        {(simulationType !== 'simulated') && (
          <>
            <FormControl style={fieldSpacingContainerStyle}>
              <Autocomplete
                id="simulationPlatforms"
                multiple
                options={platforms}
                value={platforms.filter((platform) => simulationPlatforms.includes(platform.value))}
                onChange={(_event, newValue) => {
                  const newSelectedValues = newValue.map((platform) => platform.value);
                  setSimulationPlatforms(newSelectedValues);
                }}
                getOptionLabel={(option) => option.label}
                renderInput={(params) => (
                  <TextField
                    {...params}
                    label={t_i18n('Targeted platforms')}
                    variant="standard"
                    required
                  />
                )}
                renderOption={(props, option) => (
                  <li {...props}>
                    <div className={classes.text}>{option.label ?? ''}</div>
                  </li>
                )}
              />
            </FormControl>
            <FormControl style={fieldSpacingContainerStyle}>
              <InputLabel id="simulationArchitecture">{t_i18n('Targeted architecture')}</InputLabel>
              <Select
                labelId="simulationArchitecture"
                value={simulationArchitecture}
                onChange={(event) => setSimulationArchitecture(event.target.value)}
                fullWidth
                required
              >
                <MenuItem value="AMD64">{'x86_64'}</MenuItem>
                <MenuItem value="ARM64" >{'arm64'}</MenuItem>
              </Select>
            </FormControl>
            </>
        )}
        <TextField
          label={t_i18n('Interval between injections (in minute)')}
          fullWidth
          type="number"
          value={interval}
          onChange={(event) => setInterval(Number.isNaN(parseInt(event.target.value, 10)) ? 1 : parseInt(event.target.value, 10))}
          style={fieldSpacingContainerStyle}
        />
        <FormControl style={fieldSpacingContainerStyle}>
          <InputLabel id="simulationNumberInjects">{t_i18n('Number of injects generated by attack pattern and platform')}</InputLabel>
          <Select
            labelId="selection"
            value={selection}
            onChange={(event) => setSelection(event.target.value)}
            fullWidth
          >
            <MenuItem value="multiple">{t_i18n('Multiple (limited to 5)')}</MenuItem>
            <MenuItem value="random">{t_i18n('One (random)')}</MenuItem>
          </Select>
        </FormControl>
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
            onClick={handleGenerate}
            disabled={isSubmitting || !isFormValid()}
            classes={{ root: classes.button }}
          >
            {t_i18n('Generate')}
          </Button>
        </div>
      </>
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
          {t_i18n('The scenario has been correctly generated in your OpenBAS platform')}
        </Alert>
        <Box textAlign='center' style={{ marginTop: 20 }}>
          <Button component={Link} to={result} target="_blank" variant="outlined" endIcon={<OpenInNewOutlined />}>
            {t_i18n('Access to the scenario')}
          </Button>
        </Box>
      </>
    );
  };
  const renderResultError = () => {
    return (
      <>
        <Alert icon={<ErrorOutlined fontSize="inherit" />} severity="error">
          {resultError}
        </Alert>
      </>
    );
  };
  return (
    <>
      {!oBasDisableDisplay && (
        <div className={classes.simulationResults}>
          <Tooltip title={`${t_i18n('Check the posture in OpenBAS')}`}>
            <Button
              variant="outlined"
              size="small"
              style={{
                fontSize: 12,
                color: (!isGrantedToUpdate && oBasConfigured) ? theme.palette.text.disabled : theme.palette.text.primary,
              }}
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
