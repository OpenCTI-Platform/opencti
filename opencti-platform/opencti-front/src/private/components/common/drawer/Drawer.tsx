import React, { FunctionComponent, useEffect, useState } from 'react';
import DrawerMUI from '@mui/material/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import { Add, Close, Edit } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import Fab from '@mui/material/Fab';
import classNames from 'classnames';
import { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';
import { SubscriptionAvatars } from '../../../../components/Subscription';

export enum DrawerVariant {
  create = 'create',
  update = 'update',
  createWithPanel = 'createWithPanel',
  updateWithPanel = 'updateWithPanel',
}

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
      paddingBottom: `${bannerHeightNumber}px`, // TODO ? keep it ?
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
    mainButton: {
      position: 'fixed',
      bottom: `${bannerHeightNumber + 30}px`, // TODO ? add height of banner ?
    },
    withPanel: {
      right: 230,
    },
    noPanel: {
      right: 30,
    },
  });
});

interface DrawerProps {
  title: string
  children?: React.ReactElement | null
  open?: boolean
  onClose?: () => void
  variant?: DrawerVariant
  context?: ReadonlyArray<{
    readonly focusOn: string | null
    readonly name: string
  }> | null
}

const Drawer: FunctionComponent<DrawerProps> = ({
  title,
  children,
  open: defaultOpen = false,
  onClose,
  variant,
  context,
}) => {
  const classes = useStyles();
  const [open, setOpen] = useState(defaultOpen);
  useEffect(() => {
    if (open !== defaultOpen) {
      setOpen(defaultOpen);
    }
  }, [defaultOpen]);

  const handleClose = () => {
    onClose?.();
    setOpen(false);
  };

  const update = variant ? [DrawerVariant.update, DrawerVariant.updateWithPanel].includes(variant) : undefined;
  return (
    <>
      {variant && (
        <Fab
          onClick={() => setOpen(true)}
          color="secondary"
          aria-label={update ? 'Edit' : 'Add'}
          className={classNames({
            [classes.mainButton]: true,
            [classes.withPanel]: [DrawerVariant.createWithPanel, DrawerVariant.updateWithPanel].includes(variant),
            [classes.noPanel]: [DrawerVariant.create, DrawerVariant.update].includes(variant),
          })}
        >
          {update ? <Edit /> : <Add />}
        </Fab>
      )}
      <DrawerMUI
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            onClick={handleClose}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{title}</Typography>
          {context && <SubscriptionAvatars context={context} />}
        </div>
        <div className={classes.container}>
          {children && React.cloneElement(children, { onClose: handleClose })}
        </div>
      </DrawerMUI>
    </>
  );
};

export default Drawer;
