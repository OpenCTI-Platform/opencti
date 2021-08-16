import React, { Component } from 'react';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core';
import Drawer from '@material-ui/core/Drawer';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import { CloudRefresh } from 'mdi-material-ui';
import Typography from '@material-ui/core/Typography';
import Tooltip from '@material-ui/core/Tooltip';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ExternalReferenceEnrichmentLines, {
  externalReferenceEnrichmentLinesQuery,
} from './ExternalReferenceEnrichmentLines';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
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
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
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
});

class ExternalReferenceEnrichment extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, search: '' };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false, search: '' });
  }

  render() {
    const { t, classes, externalReferenceId } = this.props;
    return (
      <div style={{ display: 'inline-block' }}>
        <Tooltip title={t('Enrichment')}>
          <IconButton
            onClick={this.handleOpen.bind(this)}
            color="primary"
            aria-label="Refresh"
          >
            <CloudRefresh />
          </IconButton>
        </Tooltip>
        <Drawer
          open={this.state.open}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize="small" />
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
  }
}

export default R.compose(
  inject18n,
  withStyles(styles),
)(ExternalReferenceEnrichment);
