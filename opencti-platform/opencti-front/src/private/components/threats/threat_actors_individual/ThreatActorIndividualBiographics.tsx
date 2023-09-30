import { Box, Grid, IconButton, Paper, Tooltip, Typography } from '@mui/material';
import { InformationOutline } from 'mdi-material-ui';
import ScaleRoundedIcon from '@mui/icons-material/ScaleRounded';
import StraightenIcon from '@mui/icons-material/Straighten';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import { makeStyles } from '@mui/styles';
import { useEffect, useState } from 'react';
import convert from 'convert';
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
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import useAuth from '../../../../utils/hooks/useAuth';
import { DEFAULT_LANG } from '../../../../utils/BrowserLanguage';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
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

const INCH = getLengthUnit(UnitSystems.Imperial);
const FOOT = getLengthUnit(UnitSystems.Imperial, true);
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
  const { me } = useAuth();
  const [unitSystem, setUnitSystem] = useState<UnitSystems>();

  // Fetch default unit system
  useEffect(() => {
    if (!unitSystem) {
      commitLocalUpdate(() => {
        let selectedSystem;
        switch (me.unit_system) {
          case 'Imperial': selectedSystem = UnitSystems.Imperial;
            break;
          case 'Metric': selectedSystem = UnitSystems.Metric;
            break;
          default: selectedSystem = UnitSystems.Auto;
        }
        const { language } = me;
        const defaultUnitSystem = validateUnitSystem(
          selectedSystem,
          language ?? DEFAULT_LANG,
        );
        setUnitSystem(defaultUnitSystem);
      });
    }
  }, []);

  const usingUSUnits = () => (unitSystem === UnitSystems.Imperial);
  const toggleUnitSystem = () => setUnitSystem(usingUSUnits()
    ? UnitSystems.Metric
    : UnitSystems.Imperial);
  const unitToggleMessage = () => (
    `Convert to ${usingUSUnits() ? UnitSystems.Metric : UnitSystems.Imperial} units`
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
      },
    );
    if (typeof validatedHeight === 'string') {
      return validatedHeight;
    }
    if ((validatedHeight as Height)?.height_cm) {
      return usingUSUnits()
        ? convert((validatedHeight as Height).height_cm, 'cm').to('in')
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
      },
    );
    if (typeof validatedWeight === 'string') {
      return validatedWeight;
    }
    if ((validatedWeight as Weight)?.weight_kg) {
      return usingUSUnits()
        ? convert((validatedWeight as Weight).weight_kg, 'kg').to('lb')
        : (validatedWeight as Weight).weight_kg;
    }
    return null;
  };

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Biographic Information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <DetailGrid title={t('Eye Color')} tooltip={t('Known observed eye color(s) for the Identity.')}>
            <ItemOpenVocab
              type="eye-color-ov"
              value={threatActorIndividual.eye_color}
              small
            />
          </DetailGrid>

          <DetailGrid title={t('Hair Color')} tooltip={t('Known observed hair color(s) for the Identity.')}>
            <ItemOpenVocab
              type="hair-color-ov"
              value={threatActorIndividual.hair_color}
              small
            />
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
              { (threatActorIndividual.height ?? []).length > 0
                ? (threatActorIndividual.height as Height[] ?? []).map((height, i) => (
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
              { (threatActorIndividual.weight ?? []).length > 0
                ? (threatActorIndividual.weight as Weight[] ?? []).map((weight, i) => (
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
