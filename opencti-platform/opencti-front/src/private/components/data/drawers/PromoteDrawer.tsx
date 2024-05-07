import React from 'react';
import Drawer from '@mui/material/Drawer';
import makeStyles from '@mui/styles/makeStyles';

import IconButton from '@mui/material/IconButton';
import { CloseOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
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
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

type DrawerContainerPropsType = {
  isOpen: boolean;
  observablesFiltered: boolean;
  onClose: () => void;
  onSubmit: () => void;
  isIndicator: boolean;
};
const PromoteDrawer = ({ isOpen, onClose, observablesFiltered, onSubmit, isIndicator }: DrawerContainerPropsType) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  return (
    <Drawer
      open={isOpen}
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      onClose={onClose}
      classes={{ paper: classes.drawerPaper }}
    >
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={onClose}
          size="large"
          color="primary"
        >
          <CloseOutlined fontSize="small" color="primary"/>
        </IconButton>
        <Typography variant="h6">
          {t_i18n('Observables and indicators conversion')}
        </Typography>
      </div>
      <div className={classes.container}>
        {!observablesFiltered && (
        <div>
          <Alert severity="warning" style={{ marginTop: 20 }}>
            {isIndicator
              ? t_i18n('This action will generate observables from the selected indicators.')
              : t_i18n('This action will generate indicators from the selected observables.')
            }
          </Alert>
        </div>
        )}
        {observablesFiltered && (
        <div>
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t_i18n('Observables')}
          </Typography>
          <Alert severity="warning" style={{ marginTop: 20 }}>
            {t_i18n(
              'This action will generate STIX patterns indicators from the selected observables.',
            )}
          </Alert>
        </div>
        )}
        <div className={classes.buttons}>
          <Button
            variant="contained"
            color="secondary"
            onClick={onSubmit}
            classes={{ root: classes.button }}
          >
            {t_i18n('Generate')}
          </Button>
        </div>
      </div>
    </Drawer>
  );
};

export default PromoteDrawer;
