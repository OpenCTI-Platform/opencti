import React, { useState } from 'react';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import { CloudRefreshOutline } from 'mdi-material-ui';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import makeStyles from '@mui/styles/makeStyles';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import ExternalReferenceEnrichmentLines, {
  externalReferenceEnrichmentLinesQuery,
} from './ExternalReferenceEnrichmentLines';

const useStyles = makeStyles((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  title: {
    float: 'left',
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: 0,
  },
}));

const ExternalReferenceEnrichment = ({ externalReferenceId }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  return (
    <div style={{ display: 'inline-block' }}>
      <Tooltip title={t('Enrichment')}>
        <IconButton
          onClick={() => setOpen(true)}
          color="inherit"
          aria-label="Refresh"
          size="large"
        >
          <CloudRefreshOutline />
        </IconButton>
      </Tooltip>
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={() => setOpen(false)}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={() => setOpen(false)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Enrichment connectors')}
          </Typography>
        </div>
        <div className={classes.container}>
          <QueryRenderer
            query={externalReferenceEnrichmentLinesQuery}
            variables={{ id: externalReferenceId }}
            render={({ props: queryProps }) => {
              if (
                queryProps
                && queryProps.externalReference
                && queryProps.connectorsForImport
              ) {
                return (
                  <ExternalReferenceEnrichmentLines
                    externalReference={queryProps.externalReference}
                    connectorsForImport={queryProps.connectorsForImport}
                  />
                );
              }
              return <div />;
            }}
          />
        </div>
      </Drawer>
    </div>
  );
};

export default ExternalReferenceEnrichment;
