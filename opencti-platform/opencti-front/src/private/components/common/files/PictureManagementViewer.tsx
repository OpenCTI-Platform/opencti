import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import React from 'react';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: '10px 15px 10px 15px',
    borderRadius: 6,
    marginTop: 2,
  },
}));

const PictureManagementViewer = () => {
  const classes = useStyles();
  const { t } = useFormatter();

  return (
    <Grid item={true} xs={6} style={{ marginTop: 40 }}>
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Pictures Management')}
        </Typography>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t('No file for the moment')}
              </span>
          </div>
        </Paper>
      </div>
    </Grid>
  );
};

export default PictureManagementViewer;
