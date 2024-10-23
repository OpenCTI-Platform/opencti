import React, { FunctionComponent } from 'react';
import IconButton from '@mui/material/IconButton';
import { ZoomInOutlined, ZoomOutOutlined, SaveOutlined } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Slide, { SlideProps } from '@mui/material/Slide';
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
      </div>
    </Drawer>
  );
};

export default StixCoreObjectContentBar;
