import { Box, Grid, IconButton, Paper, Tooltip, Typography } from '@mui/material';
import { InformationOutline } from 'mdi-material-ui';
import ScaleRoundedIcon from '@mui/icons-material/ScaleRounded';
import StraightenIcon from '@mui/icons-material/Straighten';
import parse from 'html-react-parser';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import { makeStyles } from '@mui/styles';
import { useEffect, useState } from 'react';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import {
  UnitSystems,
  getLengthUnit,
  getWeightUnit,
  validateUnitSystem,
} from '../../../../utils/UnitSystems';
import { Height, Weight, validateMeasurement } from '../../../../utils/Number';
import { commitLocalUpdate } from '../../../../relay/environment';
import { ThreatActorIndividual_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';
import { HairColors } from '../../common/form/mcas/HairColorField';
import { EyeColors } from '../../common/form/mcas/EyeColorField';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
}));

interface ListValue {
  primary: string,
  secondary: string,
}

interface FormatValue {
  unit: string,
  date: string | Date | null,
  fsd: (date: Date | string) => string,
  height?: string | number | null,
  weight?: string | number | null,
  precision?: number,
  len?: (number: string | number, toUnit?: string, fromUnit?: string, unitDisplay?: string, precision?: number) => string,
  wgt?: (number: string | number, toUnit?: string, fromUnit?: string, unitDisplay?: string, precision?: number) => string,
}

interface DetailValue {
  title: string,
  tooltip: string,
  children?: React.ReactNode,
  extra?: React.ReactNode,
}

const ListValueDisplay = ({ primary, secondary }: ListValue) => (
  <ListItem dense={true} divider={true} disablePadding={true}>
    <ListItemText primary={primary} secondary={secondary} />
  </ListItem>
);

const INCH = getLengthUnit(UnitSystems.US);
const FOOT = getLengthUnit(UnitSystems.US, true);
const isNil = (v: unknown) => v === undefined || v === null;
const isString = (v: unknown) => typeof v === 'string' || v instanceof String;

const HeightDisplay = ({ height, unit, date, len, fsd, precision }: FormatValue) => {
  if (height === undefined || height === null
    || len === undefined || len === null
    || FOOT === null) return <Typography>-</Typography>;
  const footDisplay = !isString(height) && unit === INCH
    ? ` (${len(height, FOOT, INCH, 'narrow')})`
    : '';
  const inchDisplay = !isString(height)
    ? len(height, unit, unit, 'long', precision || 0)
    : height;
  return (
    <ListValueDisplay
      primary={inchDisplay + footDisplay}
      secondary={(date ? fsd(date) : 'Unknown Date')}
    />
  );
};

const WeightDisplay = ({ weight, unit, date, wgt, fsd }: FormatValue) => {
  if (weight === undefined || weight == null
    || wgt === undefined || wgt === null) return <Typography>-</Typography>;
  const weightDisplay = !isString(weight) ? wgt(weight, unit, unit) : weight;
  return (
    <ListValueDisplay
      primary={weightDisplay as string}
      secondary={date ? fsd(date) : 'Unknown Date'}
    />
  );
};

const InfoTooltip = ({ text }: { text: string }) => (
  <Tooltip title={text}>
    <IconButton size="small" disableRipple={true} style={{ cursor: 'default' }}>
      <InformationOutline fontSize="small" color="primary" />
    </IconButton>
  </Tooltip>
);

const DetailGrid = ({ title, tooltip, children, extra }: DetailValue) => (
  <Grid item={true} xs={3} mt={-1}>
    <Box display="flex" alignItems="center">
      <Typography variant="h3" m={0}>
        {title}
      </Typography>
      <InfoTooltip text={tooltip} />
      {extra}
    </Box>
    {children}
  </Grid>
);

interface ThreatActorIndividualBiographicsComponentProps {
  threatActorIndividual: ThreatActorIndividual_ThreatActorIndividual$data
}

const ThreatActorIndividualBiographicsComponent = (
  { threatActorIndividual }: ThreatActorIndividualBiographicsComponentProps,
) => {
  const classes = useStyles();
  const { t, fsd, len, wgt } = useFormatter();

  const [unitSystem, setUnitSystem] = useState<UnitSystems>();

  // Fetch default unit system
  useEffect(() => {
    if (!unitSystem) {
      commitLocalUpdate((store: RecordSourceSelectorProxy) => {
        const me = store.getRoot().getLinkedRecord('me');
        let selectedSystem;
        switch (me?.getValue('unit_system') as string) {
          case 'US': selectedSystem = UnitSystems.US;
            break;
          case 'Metric': selectedSystem = UnitSystems.Metric;
            break;
          default: selectedSystem = UnitSystems.Auto;
        }
        const language = me?.getValue('language') as string;
        const defaultUnitSystem = validateUnitSystem(
          selectedSystem,
          language,
        );
        setUnitSystem(defaultUnitSystem);
      });
    }
  }, []);

  const usingUSUnits = () => (unitSystem === UnitSystems.US);
  const toggleUnitSystem = () => setUnitSystem(usingUSUnits()
    ? UnitSystems.Metric
    : UnitSystems.US);
  const unitToggleMessage = () => (
    `Convert to ${usingUSUnits() ? UnitSystems.Metric : UnitSystems.US} units`
  );
  const heightUnit = () => {
    let result;
    if (unitSystem) result = getLengthUnit(unitSystem);
    return result ?? '';
  };

  /**
   * @param {string | Height} height
   * @returns {number | string | null}
   */
  const heightValue = (height: string | Height): number | string | null => {
    if (isNil(height)) return null;
    const validatedHeight = validateMeasurement(
      height,
      {
        validKeys: ['height_cm', 'height_in'],
        measureType: 'length',
        defaultUnit: heightUnit(),
      },
    );
    if (typeof validatedHeight === 'string') {
      return validatedHeight;
    }
    if (validatedHeight) {
      return usingUSUnits()
        ? (validatedHeight as Height).height_in
        : (validatedHeight as Height).height_cm;
    }
    return null;
  };

  const weightUnit = () => {
    let result;
    if (unitSystem !== undefined && isString(unitSystem)) result = getWeightUnit(unitSystem);
    else if (unitSystem) result = getWeightUnit(unitSystem);
    return result ?? '';
  };

  /**
   * @param {string | Weight} weight
   * @returns {number | string | null}
   */
  const weightValue = (weight: string | Weight): number | string | null => {
    if (isNil(weight)) return null;
    const validatedWeight = validateMeasurement(
      weight,
      {
        validKeys: ['weight_kg', 'weight_lb'],
        measureType: 'weight',
        defaultUnit: weightUnit(),
      },
    );
    if (typeof validatedWeight === 'string') {
      return validatedWeight;
    }
    if (validatedWeight) {
      return usingUSUnits()
        ? (validatedWeight as Weight).weight_lb
        : (validatedWeight as Weight).weight_kg;
    }
    return null;
  };

  function toVal(value: string, dict: Record<string, string>) {
    return t(Object.values(dict)[Object.keys(dict).indexOf(value)]);
  }

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Biographic Information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <DetailGrid title={t('Eye Color')} tooltip={t('Known observed eye color(s) for the Identity.')}>
            <div id="Editeye">
              {/* Parse to verify Safe HTML */}
              {parse(
                threatActorIndividual?.x_mcas_eye_color === null
                  ? '-'
                  : toVal(threatActorIndividual.x_mcas_eye_color, EyeColors),
              )}
            </div>
          </DetailGrid>

          <DetailGrid title={t('Hair Color')} tooltip={t('Known observed hair color(s) for the Identity.')}>
            <div id="HairID">
              {/* Parse to verify Safe HTML */}
              {parse(
                threatActorIndividual?.x_mcas_hair_color === null
                  ? '-'
                  : toVal(threatActorIndividual.x_mcas_hair_color, HairColors),
              )}
            </div>
          </DetailGrid>

          <DetailGrid
            title={t('Height')}
            tooltip={t('Known observed height(s) for the Identity.')}
            extra={
              <IconButton title={unitToggleMessage()} size="small" onClick={toggleUnitSystem}>
                <StraightenIcon fontSize="small" />
              </IconButton>
            }
          >
            <List dense={true} disablePadding={true} id={'HeightIDRead'}>
              { threatActorIndividual?.x_mcas_height
                && threatActorIndividual?.x_mcas_height?.length > 0
                ? (threatActorIndividual?.x_mcas_height as Height[] ?? []).map((height, i) => (
                  <HeightDisplay
                    key={i}
                    height={heightValue(height)}
                    unit={heightUnit()}
                    date={height.date_seen}
                    len={len}
                    fsd={fsd}
                    precision={usingUSUnits() ? 0 : 2}
                  />
                )) : <ListItem dense={true} disablePadding={true}> <ListItemText primary="-" /> </ListItem>
              }
            </List>
          </DetailGrid>

          <DetailGrid
            title={t('Weight')}
            tooltip={t('Known observed weight(s) for the Individual.')}
            extra={
              <IconButton title={unitToggleMessage()} size="small" onClick={toggleUnitSystem}>
                <ScaleRoundedIcon fontSize="small" />
              </IconButton>
            }
          >
            <List dense={true} disablePadding={true} id={'WeightIDRead'}>
              { threatActorIndividual?.x_mcas_weight
                && threatActorIndividual?.x_mcas_weight?.length > 0
                ? (threatActorIndividual?.x_mcas_weight as Weight[] ?? []).map((weight, i) => (
                  <WeightDisplay
                    key={i}
                    weight={weightValue(weight)}
                    unit={weightUnit()}
                    date={weight.date_seen}
                    wgt={wgt}
                    fsd={fsd}
                  />
                )) : <ListItem dense={true} disablePadding={true}> <ListItemText primary="-" /> </ListItem>
              }
            </List>
          </DetailGrid>
        </Grid>
      </Paper>
    </div>
  );
};

export default ThreatActorIndividualBiographicsComponent;
