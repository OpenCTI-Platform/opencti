import React, { FunctionComponent } from 'react';
import IconButton from '@mui/material/IconButton';
import { CloudDownloadOutlined, ZoomInOutlined, ZoomOutOutlined, SaveOutlined } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Slide, { SlideProps } from '@mui/material/Slide';
import { Link } from 'react-router-dom';
import { FilePdfBox } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import makeStyles from '@mui/styles/makeStyles';
import { createStyles } from '@mui/styles';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Alert from '@mui/material/Alert';
import type { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';
import { useFormatter } from '../../../../components/i18n';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme, { bannerHeightNumber: number }>(() => createStyles({
  bottomNav: {
    zIndex: 1,
    display: 'flex',
    overflow: 'hidden',
    paddingBottom: ({ bannerHeightNumber }) => `${bannerHeightNumber}px`,
  },
}));

const Transition = React.forwardRef((props: SlideProps, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

interface StixCoreObjectContentBarProps {
  handleZoomIn?: () => void;
  handleZoomOut?: () => void;
  currentZoom?: number;
  handleDownload?: () => void;
  directDownload: string;
  handleDownloadPdf?: () => void;
  handleSave?: () => void;
  changed?: boolean;
  navOpen: boolean;
}

const StixCoreObjectContentBar: FunctionComponent<
StixCoreObjectContentBarProps
> = ({
  handleZoomIn,
  handleZoomOut,
  currentZoom,
  handleDownload,
  directDownload,
  handleDownloadPdf,
  handleSave,
  changed,
  navOpen,
}) => {
  const {
    bannerSettings: { bannerHeightNumber },
  } = useAuth();
  const classes = useStyles({ bannerHeightNumber });
  const enableZoom = handleZoomIn && handleZoomOut && currentZoom;
  const { t_i18n } = useFormatter();

  return (
    <Drawer
      anchor="bottom"
      variant="permanent"
      classes={{ paper: classes.bottomNav }}
      PaperProps={{ variant: 'elevation', elevation: 1 }}
    >
      <div
        style={{
          verticalAlign: 'top',
          width: '100%',
          height: 54,
          paddingTop: 3,
        }}
      >
        <div
          style={{
            float: 'left',
            marginLeft: navOpen ? 195 : 70,
            height: '100%',
            display: 'flex',
          }}
        >
          {handleSave && (
          <FormGroup>
            <FormControlLabel
              control={
                <IconButton
                  color="primary"
                  onClick={handleSave}
                  size="large"
                  disabled={!changed}
                  aria-label={t_i18n('Save')}
                >
                  <SaveOutlined />
                </IconButton>
                  }
              label={changed
                ? <Alert severity="warning">
                  {t_i18n('You have unsaved changes')}
                </Alert>
                : t_i18n('No changes detected')}
            />
          </FormGroup>
          )}
          {enableZoom && (
            <IconButton
              color="primary"
              onClick={handleZoomOut}
              disabled={currentZoom <= 0.6}
              size="large"
              aria-label={t_i18n('Zoom out')}
            >
              <ZoomOutOutlined />
            </IconButton>
          )}
          {enableZoom && (
            <IconButton
              color="primary"
              onClick={handleZoomIn}
              disabled={currentZoom >= 2}
              size="large"
              aria-label={t_i18n('Zoom in')}
            >
              <ZoomInOutlined />
            </IconButton>
          )}
        </div>
        <div
          style={{
            float: 'right',
            display: 'flex',
            height: '100%',
            marginRight: 380,
          }}
        >
          {handleDownloadPdf && (
            <Tooltip title={t_i18n('Download in pdf')}>
              <IconButton
                color="primary"
                onClick={handleDownloadPdf}
                size="large"
              >
                <FilePdfBox />
              </IconButton>
            </Tooltip>
          )}
          {directDownload ? (
            <Tooltip title={t_i18n('Download this file')}>
              <IconButton
                color="primary"
                component={Link}
                to={directDownload}
                target="_blank"
                rel="noopener noreferrer"
                size="large"
              >
                <CloudDownloadOutlined />
              </IconButton>
            </Tooltip>
          ) : (
            <Tooltip title={t_i18n('Download this file')}>
              <IconButton color="primary" onClick={handleDownload} size="large">
                <CloudDownloadOutlined />
              </IconButton>
            </Tooltip>
          )}
        </div>
      </div>
    </Drawer>
  );
};

export default StixCoreObjectContentBar;
