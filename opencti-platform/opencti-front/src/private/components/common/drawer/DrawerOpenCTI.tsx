import React, { FunctionComponent } from 'react';
import Drawer from '@mui/material/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';

const useStyles = makeStyles<Theme>((theme) => {
  const {
    bannerSettings: { bannerHeightNumber },
  } = useAuth();
  return ({
    drawerPaper: {
      minHeight: '100vh',
      width: '50%',
      position: 'fixed',
      overflow: 'auto',
      transition: theme.transitions.create('width', {
        easing: theme.transitions.easing.sharp, duration: theme.transitions.duration.enteringScreen,
      }),
      paddingTop: `${bannerHeightNumber}px`,
    },
    header: {
      backgroundColor: theme.palette.background.nav,
      padding: '10px 0',
      display: 'inline-flex',
      alignItems: 'center',
    },
    container: {
      padding: '10px 20px 20px 20px',
    },
  });
});

interface DrawerOpenCTIProps {
  title: string
  open: boolean
  setOpen: (value: boolean) => void
  children: React.ReactNode
}

const DrawerOpenCTI: FunctionComponent<DrawerOpenCTIProps> = ({
  title,
  open,
  setOpen,
  children,
}) => {
  const classes = useStyles();

  return (
    <Drawer
      open={open}
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      classes={{ paper: classes.drawerPaper }}
      onClose={() => setOpen(false)}
    >
      <div className={classes.header} >
        <IconButton
          aria-label="Close"
          onClick={() => setOpen(false)}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6">{title}</Typography>
      </div>
      <div className={classes.container}>
        {children}
      </div>
    </Drawer>
  );
};

export default DrawerOpenCTI;
