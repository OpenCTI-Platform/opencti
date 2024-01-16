import React from 'react';
import { Box, Grid, IconButton, Paper, Tooltip, Typography } from '@mui/material';
import { InformationOutline } from 'mdi-material-ui';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import { makeStyles } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import { ThreatActorIndividual_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import { isEmptyField } from '../../../../utils/utils';
import useUserMetric from '../../../../utils/hooks/useUserMetric';

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
  primary: string;
  secondary: string;
}

interface FormatValue {
  date: string | Date | null;
  height?: number | null;
  weight?: number | null;
}

interface DetailValue {
  title: string;
  tooltip: string;
  children?: React.ReactNode;
  extra?: React.ReactNode;
}

const ListValueDisplay = ({ primary, secondary }: ListValue) => (
  <ListItem dense={true} divider={true} disablePadding={true}>
    <ListItemText primary={primary} secondary={secondary} />
  </ListItem>
);

const HeightDisplay = ({ height, date }: FormatValue) => {
  const { fsd } = useFormatter();
  const { lengthPrimaryUnit, len } = useUserMetric();
  if (isEmptyField(height)) return <Typography>-</Typography>;
  const inchDisplay = len(height);
  return (
    <ListValueDisplay
      primary={`${inchDisplay} ${lengthPrimaryUnit}`}
      secondary={date ? fsd(date) : 'Unknown Date'}
    />
  );
};

const WeightDisplay = ({ weight, date }: FormatValue) => {
  const { fsd } = useFormatter();
  const { weightPrimaryUnit, wgt } = useUserMetric();
  if (isEmptyField(weight)) return <Typography>-</Typography>;
  const weightDisplay = wgt(weight);
  return (
    <ListValueDisplay
      primary={`${weightDisplay} ${weightPrimaryUnit}`}
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
  threatActorIndividual: ThreatActorIndividual_ThreatActorIndividual$data;
}

const ThreatActorIndividualBiographicsComponent = ({
  threatActorIndividual,
}: ThreatActorIndividualBiographicsComponentProps) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Biographic Information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <DetailGrid
            title={t_i18n('Eye Color')}
            tooltip={t_i18n('Known observed eye color(s) for the Identity.')}
          >
            <ItemOpenVocab
              type="eye-color-ov"
              value={threatActorIndividual.eye_color}
              small
            />
          </DetailGrid>

          <DetailGrid
            title={t_i18n('Hair Color')}
            tooltip={t_i18n('Known observed hair color(s) for the Identity.')}
          >
            <ItemOpenVocab
              type="hair-color-ov"
              value={threatActorIndividual.hair_color}
              small
            />
          </DetailGrid>

          <DetailGrid
            title={t_i18n('Height')}
            tooltip={t_i18n('Known observed height(s) for the Identity.')}
          >
            <List dense={true} disablePadding={true} id={'HeightIDRead'}>
              {(threatActorIndividual.height ?? []).length > 0 ? (
                (threatActorIndividual.height ?? []).map((height, i) => (
                  <HeightDisplay
                    key={i}
                    height={height?.measure}
                    date={height?.date_seen}
                  />
                ))
              ) : (
                <ListItem dense={true} disablePadding={true}>
                  {' '}
                  <ListItemText primary="-" />{' '}
                </ListItem>
              )}
            </List>
          </DetailGrid>

          <DetailGrid
            title={t_i18n('Weight')}
            tooltip={t_i18n('Known observed weight(s) for the Individual.')}
          >
            <List dense={true} disablePadding={true} id={'WeightIDRead'}>
              {(threatActorIndividual.weight ?? []).length > 0 ? (
                (threatActorIndividual.weight ?? []).map((weight, i) => (
                  <WeightDisplay
                    key={i}
                    weight={weight?.measure}
                    date={weight?.date_seen}
                  />
                ))
              ) : (
                <ListItem dense={true} disablePadding={true}>
                  {' '}
                  <ListItemText primary="-" />{' '}
                </ListItem>
              )}
            </List>
          </DetailGrid>
        </Grid>
      </Paper>
    </div>
  );
};

export default ThreatActorIndividualBiographicsComponent;
