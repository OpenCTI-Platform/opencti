import React, { CSSProperties, useEffect, useState } from 'react';
import DrawerMUI from '@mui/material/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import { Add, Close, Edit } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import Fab from '@mui/material/Fab';
import classNames from 'classnames';
import { createStyles } from '@mui/styles';
import { GenericContext } from '../model/GenericContextModel';
import type { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';
import { SubscriptionAvatars } from '../../../../components/Subscription';

export enum DrawerVariant {
  create = 'create',
  update = 'update',
  createWithPanel = 'createWithPanel',
  createWithLargePanel = 'createWithLargePanel',
  updateWithPanel = 'updateWithPanel',
}

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme, { bannerHeightNumber: number }>((theme) => createStyles({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    paddingTop: ({ bannerHeightNumber }) => `${bannerHeightNumber}px`,
    paddingBottom: ({ bannerHeightNumber }) => `${bannerHeightNumber}px`,
  },
  header: {
    backgroundColor: theme.palette.mode === 'light' ? theme.palette.background.default : theme.palette.background.nav,
    padding: '10px 0',
    display: 'inline-flex',
    alignItems: 'center',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  mainButton: ({ bannerHeightNumber }) => ({
    position: 'fixed',
    bottom: `${bannerHeightNumber + 30}px`,
  }),
  withLargePanel: {
    right: 280,
  },
  withPanel: {
    right: 230,
  },
  noPanel: {
    right: 30,
  },
}));

export interface DrawerControlledDialProps {
  onOpen: () => void;
  onClose: () => void;
}
export type DrawerControlledDialType = ({ onOpen, onClose }: DrawerControlledDialProps) => React.ReactElement;

interface DrawerProps {
  title: string;
  children?:
  | ((props: { onClose: () => void }) => React.ReactElement)
  | React.ReactElement
  | null;
  open?: boolean;
  onClose?: () => void;
  variant?: DrawerVariant;
  context?: readonly (GenericContext | null)[] | null;
  header?: React.ReactElement;
  controlledDial?: DrawerControlledDialType;
  containerRef?: HTMLInputElement;
  containerStyle?: CSSProperties
}

const Drawer = ({
  title,
  children,
  open: defaultOpen = false,
  onClose,
  variant,
  context,
  header,
  controlledDial,
  containerRef,
  containerStyle,
}: DrawerProps) => {
  const {
    bannerSettings: { bannerHeightNumber },
  } = useAuth();
  const classes = useStyles({ bannerHeightNumber });
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

  const update = variant
    ? [DrawerVariant.update, DrawerVariant.updateWithPanel].includes(variant)
    : undefined;
  let component;
  if (children) {
    if (typeof children === 'function') {
      component = children({ onClose: handleClose });
    } else {
      component = React.cloneElement(children as React.ReactElement, {
        onClose: handleClose,
      });
    }
  }
  return (
    <>
      {controlledDial ? controlledDial({ onOpen: () => setOpen(true), onClose: handleClose }) : undefined }
      {variant && (
        <Fab
          onClick={() => setOpen(true)}
          color="primary"
          aria-label={update ? 'Edit' : 'Add'}
          className={classNames({
            [classes.mainButton]: true,
            [classes.withPanel]: [
              DrawerVariant.createWithPanel,
              DrawerVariant.updateWithPanel,
            ].includes(variant),
            [classes.withLargePanel]: [
              DrawerVariant.createWithLargePanel,
            ].includes(variant),
            [classes.noPanel]: [
              DrawerVariant.create,
              DrawerVariant.update,
            ].includes(variant),
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
        PaperProps={{
          ref: containerRef,
        }}
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
          <Typography variant="subtitle2" style={{ textWrap: 'nowrap' }}>{title}</Typography>
          {context && <SubscriptionAvatars context={context} />}
          {header}
        </div>
        <div className={classes.container} style={containerStyle}>{component}</div>
      </DrawerMUI>
    </>
  );
};

export default Drawer;
