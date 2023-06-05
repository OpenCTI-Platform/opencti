import React, { FunctionComponent } from 'react';
import IconButton from '@mui/material/IconButton';
import {
  CloudDownloadOutlined,
  EditOutlined,
  ZoomInOutlined,
  ZoomOutOutlined,
} from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Slide, { SlideProps } from '@mui/material/Slide';
import { Link } from 'react-router-dom';
import { FilePdfBox } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import makeStyles from '@mui/styles/makeStyles';

const useStyles = makeStyles(() => ({
  bottomNav: {
    zIndex: 1000,
    display: 'flex',
    overflow: 'hidden',
  },
}));

const Transition = React.forwardRef((props: SlideProps, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

interface StixDomainObjectContentBarProps {
  handleZoomIn?: () => void;
  handleZoomOut?: () => void;
  currentZoom?: number;
  handleDownload?: () => void;
  directDownload: string;
  handleDownloadPdf?: () => void;
  handleSwitchReadOnly?: () => void;
  readOnly?: boolean;
  navOpen: boolean;
}

const StixDomainObjectContentBar: FunctionComponent<
StixDomainObjectContentBarProps
> = ({
  handleZoomIn,
  handleZoomOut,
  currentZoom,
  handleDownload,
  directDownload,
  handleDownloadPdf,
  handleSwitchReadOnly,
  readOnly,
  navOpen,
}) => {
  const classes = useStyles();
  const enableZoom = handleZoomIn && handleZoomOut && currentZoom;
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
          {handleSwitchReadOnly && (
            <IconButton
              color={readOnly ? 'primary' : 'secondary'}
              onClick={handleSwitchReadOnly}
              size="large"
            >
              <EditOutlined />
            </IconButton>
          )}
          {enableZoom && (
            <IconButton
              color="primary"
              onClick={handleZoomOut}
              disabled={currentZoom <= 0.6}
              size="large"
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
            <Tooltip title={'Download in pdf'}>
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
            <Tooltip title={'Download this file'}>
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
            <Tooltip title={'Download this file'}>
              <IconButton color="primary" onClick={handleDownload}>
                <CloudDownloadOutlined />
              </IconButton>
            </Tooltip>
          )}
        </div>
      </div>
    </Drawer>
  );
};

export default StixDomainObjectContentBar;
