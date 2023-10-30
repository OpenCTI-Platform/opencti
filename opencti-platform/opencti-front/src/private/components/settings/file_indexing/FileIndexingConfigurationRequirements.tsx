import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 20,
    borderRadius: 6,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

interface FileIndexingConfigurationRequirementsProps {
  isModuleWarning: boolean
}

const FileIndexingConfigurationRequirements: FunctionComponent<FileIndexingConfigurationRequirementsProps> = ({
  isModuleWarning,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  return (
    <Grid container={true} spacing={3} classes={{ container: classes.gridContainer }}>
      <Grid item={true} xs={12}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Requirements')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Alert
            severity={isModuleWarning ? 'warning' : 'info'}
            variant="outlined"
            style={{ position: 'relative' }}
            >
            {t('File indexing needs one of these requirements: ')}
              <ul>
                <li>Elasticsearch &gt;= 8.4</li>
                <li>Elasticsearch &lt; 8.4 with ingest-attachment plugin</li>
                <li>OpenSearch with ingest-attachment plugin</li>
              </ul>
          </Alert>
        </Paper>
    </Grid>
</Grid>
  );
};

export default FileIndexingConfigurationRequirements;
