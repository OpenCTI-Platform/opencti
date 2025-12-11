import React, { Component } from 'react';
import { CSVLink } from 'react-csv';
import { ExploreOutlined, GetAppOutlined, ImageOutlined } from '@mui/icons-material';
import { FileDelimitedOutline, FileExportOutline, FilePdfBox } from 'mdi-material-ui';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import * as R from 'ramda';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Dialog from '@mui/material/Dialog';
import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import { commitLocalUpdate, MESSAGING$ } from '../relay/environment';
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

const DELAY = 1000;

const wait = async (delay = DELAY) => {
  await new Promise((resolve) => {
    setTimeout(resolve, delay);
  });
};

class ExportButtons extends Component {
  constructor(props) {
    super(props);
    this.adjust = props.adjust;
    this.csvLink = React.createRef();

    this.state = {
      anchorElImage: null,
      anchorElPdf: null,
      exporting: false,
    };
  }

  handleOpenImage(event) {
    this.setState({ anchorElImage: event.currentTarget });
  }

  handleCloseImage() {
    this.setState({ anchorElImage: null });
  }

  async exportImage({ domElementId, name, themeId, background, themes, userThemeId }) {
    this.setState({ exporting: true });

    this.handleCloseImage();
    const { pixelRatio = 1, t } = this.props;

    // let some delay to display the loading state
    await wait();

    commitLocalUpdate((store) => {
      const me = store.getRoot().getLinkedRecord('me');
      me.setValue(themeId, 'theme');
    });

    const container = document.getElementById(domElementId);

    const exportButtons = document.getElementById('export-buttons');
    exportButtons?.setAttribute('style', 'display: none');

    const viewButtons = document.getElementById('container-view-buttons');
    viewButtons?.setAttribute('style', 'display: none');

    const { offsetWidth, offsetHeight } = container;
    // former condition, but don't understand its purpose
    if (themeId === userThemeId && this.adjust) {
      container.setAttribute('style', 'width:3840px; height:2160px');
      this.adjust(true);
    }

    try {
      const selectedTheme = themes.edges.find(
        (edge) => edge.node.id === themeId,
      )?.node;

      // add some delay to permit the ui to re-render with the selected theme
      await wait();

      await exportImage(
        domElementId,
        offsetWidth,
        offsetHeight,
        name,
        background ? selectedTheme?.theme_background : null,
        pixelRatio,
        this.adjust,
      );
    } catch {
      MESSAGING$.notifyError(t('Dashboard cannot be exported to image'));
    } finally {
      exportButtons?.setAttribute('style', 'display: block');
      viewButtons?.setAttribute('style', 'display: block, marginLeft: theme.spacing(2)');

      commitLocalUpdate((store) => {
        const me = store.getRoot().getLinkedRecord('me');
        me.setValue(userThemeId, 'theme');
      });

      this.setState({ exporting: false });
    }
  }

  handleOpenPdf(event) {
    this.setState({ anchorElPdf: event.currentTarget });
  }

  handleClosePdf() {
    this.setState({ anchorElPdf: null });
  }

  async exportPdf({ domElementId, name, themeId, background, themes, userThemeId }) {
    this.setState({ exporting: true });
    this.handleClosePdf();

    const { pixelRatio = 1, t } = this.props;

    // add some delay to display loading state
    await wait();

    commitLocalUpdate((store) => {
      const me = store.getRoot().getLinkedRecord('me');
      me.setValue(themeId, 'theme');
    });

    const buttons = document.getElementById('export-buttons');
    buttons.setAttribute('style', 'display: none');

    const selectedTheme = themes.edges.find(
      (edge) => edge.node.id === themeId,
    )?.node;

    try {
      // add some delay to permit the ui to re-render with the selected theme
      await wait();

      await exportPdf(
        domElementId,
        name,
        background ? selectedTheme?.theme_background : null,
        pixelRatio,
        this.adjust,
      );
    } catch (_e) {
      MESSAGING$.notifyError(t('Dashboard cannot be exported to pdf'));
    } finally {
      commitLocalUpdate((store) => {
        const me = store.getRoot().getLinkedRecord('me');
        me.setValue(userThemeId, 'theme');
      });

      this.setState({ exporting: false });
      buttons.setAttribute('style', 'display: block');
    }
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
    } = this.props;
    return (
      <UserContext.Consumer>
        {({ me, themes }) => {
          const isInDraft = me.draftContext;
          return (
            <div className={classes.exportButtons} id="export-buttons">
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
                {themes.edges.flatMap(({ node }) => [
                  <MenuItem
                    key={`${node.id}-with-bg`}
                    onClick={() => this.exportImage({
                      domElementId,
                      name,
                      themeId: node.id,
                      background: true,
                      themes,
                      userThemeId: me.theme,
                    })}
                  >
                    {node.name} {t('(with background)')}
                  </MenuItem>,
                  <MenuItem
                    key={`${node.id}-without-bg`}
                    onClick={() => this.exportImage({
                      domElementId,
                      name,
                      themeId: node.id,
                      background: false,
                      themes,
                      userThemeId: me.theme,
                    })}
                  >
                    {node.name} {t('(without background)')}
                  </MenuItem>,
                ])}
              </Menu>

              <Menu
                anchorEl={anchorElPdf}
                open={Boolean(anchorElPdf)}
                onClose={this.handleClosePdf.bind(this)}
              >
                {
                  themes.edges.map(({ node }) => (
                    <MenuItem
                      key={node.id}
                      onClick={() => this.exportPdf({
                        domElementId,
                        name,
                        themeId: node.id,
                        background: true,
                        themes,
                        userThemeId: me.theme,
                      })}
                    >
                      {node.name}
                    </MenuItem>
                  ))
                }
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
