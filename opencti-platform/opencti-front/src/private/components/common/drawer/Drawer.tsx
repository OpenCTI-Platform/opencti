import DrawerHeader from '@common/drawer/DrawerHeader';
import Button from '@common/button/Button';
import DrawerMUI from '@mui/material/Drawer';
import { MenuBookOutlined } from '@mui/icons-material';
import { createStyles, useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import { fdsLayerClass, layerInputVars, SURFACE_LAYER } from '../../../../utils/fdsLayer';
import React, { CSSProperties, forwardRef, isValidElement, useEffect, useState } from 'react';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';
import { GenericContext } from '../model/GenericContextModel';
import { Stack, SxProps } from '@mui/material';

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
    display: 'flex',
    flexDirection: 'column',
    gap: theme.spacing(2),
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
  context?: readonly (GenericContext | null)[] | null;
  header?: React.ReactElement;
  /** The documentation of what the drawer creates or edits, linked from the header next to the close button */
  learnMore?: { href: string; testId?: string };
  subHeader?: {
    right?: React.ReactElement[];
    left?: React.ReactElement[];
  };
  controlledDial?: DrawerControlledDialType;
  containerStyle?: CSSProperties;
  disabled?: boolean;
  size?: DrawerSize;
  sx?: SxProps;
  disableBackdropClose?: boolean;
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
  context,
  header,
  learnMore,
  subHeader,
  controlledDial,
  containerStyle,
  size = 'large',
  disableBackdropClose = false,
}: DrawerProps, ref) => {
  const {
    bannerSettings: { bannerHeightNumber },
  } = useAuth();

  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
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

  let component;
  if (children) {
    if (typeof children === 'function') {
      component = children({ onClose: handleClose });
    } else if (isValidElement(children) && children.type === React.Fragment) {
      // Fragments don't accept props, so we can't pass onClose to them
      component = children;
    } else {
      component = React.cloneElement(children as React.ReactElement, {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        onClose: handleClose,
      });
    }
  }

  const renderSubHeader = () => {
    if (!subHeader) return null;

    if (subHeader.left && subHeader.right) {
      return (
        <Stack direction="row" justifyContent="space-between">
          <Stack direction="row" gap={1}>
            {subHeader.left}
          </Stack>
          <Stack direction="row" gap={1}>
            {subHeader.right}
          </Stack>
        </Stack>
      );
    }

    if (subHeader.left && !subHeader.right) {
      return (
        <Stack direction="row" gap={1}>
          {subHeader.left}
        </Stack>
      );
    }

    if (!subHeader.left && subHeader.right) {
      return (
        <Stack direction="row" gap={1} justifyContent="flex-end">
          {subHeader.right}
        </Stack>
      );
    }
  };

  return (
    <>
      {controlledDial && (
        // issue with calling controlledDial as function, so all hooks inside controlledDial func are counted
        // as Drawer hook list, when undefined, the hooks disapear, breaks the rules of hooks
        // -> creating new element will separate component with isolated hooks tree
        React.createElement(controlledDial, { onOpen: () => setOpen(true), onClose: handleClose })
      )}
      <DrawerMUI
        open={open}
        anchor="right"
        variant="temporary"
        elevation={1}
        onClose={disableBackdropClose
          ? (_, reason) => {
              if (reason !== 'backdropClick') {
                handleClose();
              }
            }
          : handleClose}
        sx={{
          zIndex: 1202,
        }}
        slotProps={{
          paper: {
            ref,
            className: fdsLayerClass(SURFACE_LAYER),
            'aria-modal': 'true',
            'aria-labelledby': 'drawer-title',
            role: 'dialog',
            sx: {
              ...layerInputVars,
              minHeight: '100vh',
              width: getDrawerWidth(size),
              position: 'fixed',
              overflow: 'hidden',
              transition: theme.transitions.create('width', {
                easing: theme.transitions.easing.sharp,
                duration: theme.transitions.duration.enteringScreen,
              }),
              paddingTop: `${bannerHeightNumber}px`,
              paddingBottom: `${bannerHeightNumber}px`,
              backgroundColor: 'var(--bg-elevation-default)',
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
              {learnMore && (
                <Button
                  variant="tertiary"
                  size="small"
                  startIcon={<MenuBookOutlined fontSize="small" />}
                  href={learnMore.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  data-testid={learnMore.testId}
                >
                  {t_i18n('Learn more')}
                </Button>
              )}
            </>
          )}
          onClose={handleClose}
        />

        <div
          className={classes.container}
          style={{
            ...containerStyle,
            backgroundColor: 'var(--bg-elevation-default)',
          }}
        >
          {renderSubHeader()}
          {component}
        </div>
      </DrawerMUI>
    </>
  );
});

export default Drawer;
