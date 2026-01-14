import DrawerHeader from '@common/drawer/DrawerHeader';
import { Add, Edit } from '@mui/icons-material';
import DrawerMUI from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { createStyles, useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import classNames from 'classnames';
import React, { CSSProperties, forwardRef, useEffect, useState } from 'react';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import type { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';
import { GenericContext } from '../model/GenericContextModel';
import { SxProps } from '@mui/material';

export enum DrawerVariant {
  create = 'create',
  update = 'update',
  createWithPanel = 'createWithPanel',
  createWithLargePanel = 'createWithLargePanel',
  updateWithPanel = 'updateWithPanel',
}

export type DrawerSize = 'small' | 'medium' | 'large' | 'extraLarge';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme, { bannerHeightNumber: number }>((theme) => createStyles({
  header: {
    backgroundColor: theme.palette.mode === 'light' ? theme.palette.background.default : theme.palette.background.nav,
    padding: '10px 0',
    display: 'inline-flex',
    alignItems: 'center',
  },
  container: {
    padding: theme.spacing(3),
    height: '100%',
    overflowY: 'auto',
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
  onClose?: () => void;
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
  containerStyle?: CSSProperties;
  disabled?: boolean;
  size?: DrawerSize;
  sx?: SxProps;
}

const getDrawerWidth = (size: DrawerSize) => {
  switch (size) {
    case 'small': return '420px';
    case 'medium': return '640px';
    case 'large': return '960px';
    case 'extraLarge': return '90vw';
  }
};

// eslint-disable-next-line react/display-name
const Drawer = forwardRef<HTMLDivElement, DrawerProps>(({
  title,
  children,
  open: defaultOpen = false,
  onClose,
  variant,
  context,
  header,
  controlledDial,
  containerStyle,
  disabled = false,
  size = 'large',
}: DrawerProps, ref) => {
  const {
    bannerSettings: { bannerHeightNumber },
  } = useAuth();

  const theme = useTheme<Theme>();
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
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
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
          disabled={disabled}
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
        onClose={handleClose}
        onClick={(e) => e.stopPropagation()}
        sx={{
          zIndex: 1202,
        }}
        slotProps={{
          paper: {
            ref,
            sx: {
              minHeight: '100vh',
              width: getDrawerWidth(size),
              position: 'fixed',
              overflow: 'auto',
              transition: theme.transitions.create('width', {
                easing: theme.transitions.easing.sharp,
                duration: theme.transitions.duration.enteringScreen,
              }),
              paddingTop: `${bannerHeightNumber}px`,
              paddingBottom: `${bannerHeightNumber}px`,
            },
          },
        }}
      >
        <DrawerHeader
          title={title}
          endContent={(
            <>
              {context && <SubscriptionAvatars context={context} />}
              {header}
            </>
          )}
          onClose={handleClose}
        />
        <div
          className={classes.container}
          style={{
            ...containerStyle,
            backgroundColor: theme.palette.background.drawer,
          }}
        >
          {component}
        </div>
      </DrawerMUI>
    </>
  );
});

export default Drawer;
