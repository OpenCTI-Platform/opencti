import React, { Component } from 'react';
import { CSVLink } from 'react-csv';
import { ContentCopyOutlined, ExploreOutlined, GetAppOutlined, ImageOutlined } from '@mui/icons-material';
import { FileDelimitedOutline, FileExportOutline, FilePdfBox } from 'mdi-material-ui';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import * as R from 'ramda';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Dialog from '@mui/material/Dialog';
import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import themeLight from './ThemeLight';
import themeDark from './ThemeDark';
import { commitLocalUpdate } from '../relay/environment';
import { exportImage, exportPdf } from '../utils/Image';
import inject18n from './i18n';
import Loader from './Loader';
import { UserContext } from '../utils/hooks/useAuth';
import withRouter from '../utils/compat_router/withRouter';
import { KNOWLEDGE_KNFRONTENDEXPORT } from '../utils/hooks/useGranted';
import Security from '../utils/Security';

const styles = () => ({
  exportButtons: {
    display: 'flex',
  },
  loader: {
    backgroundColor: 'rgba(0, 0, 0, 0.8)',
  },
});

class ExportButtons extends Component {
  constructor(props) {
    super(props);
    this.adjust = props.adjust;
    this.csvLink = React.createRef();
    commitLocalUpdate((store) => {
      const me = store.getRoot().getLinkedRecord('me');
      const exporting = me.getValue('exporting') || false;
      this.state = {
        anchorElImage: null,
        anchorElPdf: null,
        exporting,
      };
    });
  }

  handleOpenImage(event) {
    this.setState({ anchorElImage: event.currentTarget });
  }

  handleCloseImage() {
    this.setState({ anchorElImage: null });
  }

  exportImage(domElementId, name, theme, background) {
    this.setState({ exporting: true });
    this.handleCloseImage();
    const { theme: currentTheme, pixelRatio = 1 } = this.props;
    let timeout = 4000;
    if (theme !== currentTheme.palette.mode) {
      timeout = 6000;
      commitLocalUpdate((store) => {
        const me = store.getRoot().getLinkedRecord('me');
        me.setValue(theme, 'theme');
        me.setValue(true, 'exporting');
      });
    }
    setTimeout(() => {
      const container = document.getElementById(domElementId);
      const buttons = document.getElementById('export-buttons');
      buttons.setAttribute('style', 'display: none');
      const { offsetWidth, offsetHeight } = container;
      if (theme === currentTheme.palette.mode && this.adjust) {
        container.setAttribute('style', 'width:3840px; height:2160px');
        this.adjust(true);
      }
      setTimeout(() => {
        exportImage(
          domElementId,
          offsetWidth,
          offsetHeight,
          name,
          // eslint-disable-next-line no-nested-ternary
          background
            ? theme === 'light'
              ? themeLight().palette.background.default
              : themeDark().palette.background.default
            : null,
          pixelRatio,
          this.adjust,
        ).then(() => {
          buttons.setAttribute('style', 'display: block');
          commitLocalUpdate((store) => {
            const me = store.getRoot().getLinkedRecord('me');
            me.setValue(false, 'exporting');
            me.setValue(currentTheme.palette.mode, 'theme');
          });
          this.setState({ exporting: false });
        });
      }, timeout / 2);
    }, timeout);
  }

  handleOpenPdf(event) {
    this.setState({ anchorElPdf: event.currentTarget });
  }

  handleClosePdf() {
    this.setState({ anchorElPdf: null });
  }

  exportPdf(domElementId, name, theme, background) {
    this.setState({ exporting: true });
    this.handleClosePdf();
    const { theme: currentTheme, pixelRatio = 1 } = this.props;
    let timeout = 4000;
    if (theme !== currentTheme.palette.mode) {
      timeout = 6000;
      commitLocalUpdate((store) => {
        const me = store.getRoot().getLinkedRecord('me');
        me.setValue(true, 'exporting');
        me.setValue(theme, 'theme');
      });
    }
    setTimeout(() => {
      const buttons = document.getElementById('export-buttons');
      buttons.setAttribute('style', 'display: none');
      exportPdf(
        domElementId,
        name,
        // eslint-disable-next-line no-nested-ternary
        background
          ? theme === 'light'
            ? themeLight().palette.background.default
            : themeDark().palette.background.default
          : null,
        pixelRatio,
        this.adjust,
      ).then(() => {
        buttons.setAttribute('style', 'display: block');
        commitLocalUpdate((store) => {
          const me = store.getRoot().getLinkedRecord('me');
          me.setValue(false, 'exporting');
          me.setValue(currentTheme.palette.mode, 'theme');
        });
        this.setState({ exporting: false });
      });
    }, timeout);
  }

  render() {
    const { anchorElImage, anchorElPdf, exporting } = this.state;
    const {
      classes,
      t,
      domElementId,
      name,
      type,
      csvData,
      csvFileName,
      containerId,
      handleDownloadAsStixReport,
      handleExportDashboard,
      investigationAddFromContainer,
      navigate,
      handleDashboardDuplication,
      variant,
    } = this.props;
    return (
      <UserContext.Consumer>
        {({ me }) => {
          const isInDraft = me.draftContext;
          return (
            <div className={classes.exportButtons} id="export-buttons">
              {handleDashboardDuplication && variant === 'dashboard' && (
              <Tooltip title={t('Duplicate the dashboard')}>
                <ToggleButton
                  size="small"
                  value="duplicate-dashboard"
                  onClick={handleDashboardDuplication.bind(this)}
                  style={{ marginRight: 3 }}
                >
                  <ContentCopyOutlined fontSize="small" color="primary" />
                </ToggleButton>
              </Tooltip>
              )}
              <Security needs={[KNOWLEDGE_KNFRONTENDEXPORT]}>
                <Tooltip title={t('Export to image')}>
                  <ToggleButton size="small" onClick={this.handleOpenImage.bind(this)} value={'Export-to-image'} style={{ marginRight: 3 }}>
                    <ImageOutlined fontSize="small" color="primary" />
                  </ToggleButton>
                </Tooltip>
              </Security>
              <Security needs={[KNOWLEDGE_KNFRONTENDEXPORT]}>
                <Tooltip title={t('Export to PDF')}>
                  <ToggleButton size="small" onClick={this.handleOpenPdf.bind(this)} value={'Export-to-PDF'} style={{ marginRight: 3 }}>
                    <FilePdfBox fontSize="small" color="primary" />
                  </ToggleButton>
                </Tooltip>
              </Security>
              {type === 'dashboard' && handleExportDashboard && (
              <Tooltip title={t('Export')}>
                <ToggleButton
                  size="small"
                  onClick={handleExportDashboard.bind(this)}
                  value={'Export-to-JSON'}
                  style={{ marginRight: 3 }}
                >
                  <FileExportOutline fontSize="small" color="primary" />
                </ToggleButton>
              </Tooltip>
              )}
              {investigationAddFromContainer && (
              <Tooltip title={isInDraft ? t('Not available in draft') : t('Start an investigation')}>
                <ToggleButton
                  size="small"
                  value={isInDraft ? 'Not available in draft' : 'Start-an-investigation'}
                  onClick={!isInDraft && investigationAddFromContainer.bind(
                    this,
                    containerId,
                    navigate,
                  )}
                  style={{ marginRight: 3 }}
                >
                  <ExploreOutlined fontSize="small" color={!isInDraft ? 'primary' : 'disabled'} />
                </ToggleButton>
              </Tooltip>
              )}
              {type === 'investigation' && (
              <Tooltip title={t('Download as STIX report')}>
                <ToggleButton size="small" onClick={handleDownloadAsStixReport.bind(this)} value={'Download-as-STIX-report'} style={{ marginRight: 3 }}>
                  <GetAppOutlined fontSize="small" color="primary" />
                </ToggleButton>
              </Tooltip>
              )}
              {csvData && (
              <Tooltip title={t('Export to CSV')}>
                <ToggleButton size="small" onClick={() => this.csvLink.current.link.click()} value={'Export-to-CSV'} style={{ marginRight: 3 }}>
                  <FileDelimitedOutline fontSize="small" color="primary" />
                </ToggleButton>
              </Tooltip>
              )}
              <Menu
                anchorEl={anchorElImage}
                open={Boolean(anchorElImage)}
                onClose={this.handleCloseImage.bind(this)}
              >
                <MenuItem
                  onClick={this.exportImage.bind(
                    this,
                    domElementId,
                    name,
                    'dark',
                    true,
                  )}
                >
                  {t('Dark (with background)')}
                </MenuItem>
                <MenuItem
                  onClick={this.exportImage.bind(
                    this,
                    domElementId,
                    name,
                    'dark',
                    false,
                  )}
                >
                  {t('Dark (without background)')}
                </MenuItem>
                <MenuItem
                  onClick={this.exportImage.bind(
                    this,
                    domElementId,
                    name,
                    'light',
                    true,
                  )}
                >
                  {t('Light (with background)')}
                </MenuItem>
                <MenuItem
                  onClick={this.exportImage.bind(
                    this,
                    domElementId,
                    name,
                    'light',
                    false,
                  )}
                >
                  {t('Light (without background)')}
                </MenuItem>
              </Menu>
              <Menu
                anchorEl={anchorElPdf}
                open={Boolean(anchorElPdf)}
                onClose={this.handleClosePdf.bind(this)}
              >
                <MenuItem
                  onClick={this.exportPdf.bind(
                    this,
                    domElementId,
                    name,
                    'dark',
                    true,
                  )}
                >
                  {t('Dark')}
                </MenuItem>
                <MenuItem
                  onClick={this.exportPdf.bind(
                    this,
                    domElementId,
                    name,
                    'light',
                    true,
                  )}
                >
                  {t('Light')}
                </MenuItem>
              </Menu>
              <Dialog
                slotProps={{ paper: { elevation: 1 } }}
                open={exporting}
                keepMounted={true}
                fullScreen={true}
                classes={{ paper: classes.loader }}
              >
                <Loader />
              </Dialog>
              {csvData && (
              <CSVLink
                filename={csvFileName || `${t('CSV data.')}.csv`}
                ref={this.csvLink}
                data={csvData}
              />
              )}
            </div>
          );
        }}
      </UserContext.Consumer>
    );
  }
}

export default R.compose(
  inject18n,
  withTheme,
  withRouter,
  withStyles(styles),
)(ExportButtons);
