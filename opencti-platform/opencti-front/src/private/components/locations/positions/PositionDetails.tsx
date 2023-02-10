import React, { FunctionComponent } from 'react';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { Position_position$data } from './__generated__/Position_position.graphql';
import { Theme } from '../../../../components/Theme';

const styles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    borderRadius: 5,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
}));

interface PositionDetailsProps {
  position: Position_position$data
}

const PositionDetails: FunctionComponent<PositionDetailsProps> = ({ position }) => {
  const { t } = useFormatter();
  const classes = styles();

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Description')}
            </Typography>
            {position.description && (
              <ExpandableMarkdown
                source={position.description}
                limit={300}
              />
            )}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Latitude')}
            </Typography>
            {position.latitude && (
              <ExpandableMarkdown
                source={position.latitude.toString()}
                limit={300}
              />
            )}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Longitude')}
            </Typography>
            {position.longitude && (
              <ExpandableMarkdown
                source={position.longitude.toString()}
                limit={300}
              />
            )}
          </Grid>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Street address')}
            </Typography>
            {position.street_address && (
              <ExpandableMarkdown
                source={position.street_address}
                limit={300}
              />
            )}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Postal code')}
            </Typography>
            {position.postal_code && (
              <ExpandableMarkdown
                source={position.postal_code}
                limit={300}
              />
            )}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('City')}
            </Typography>
            {position.city?.name && (
              <Chip
                key={position.city.name}
                classes={{ root: classes.chip }}
                label={position.city.name}
              />
            )}
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default PositionDetails;
