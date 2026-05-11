import DrawerHeader from '@common/drawer/DrawerHeader';
import { Add, Edit } from '@mui/icons-material';
import DrawerMUI from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { createStyles, useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import classNames from 'classnames';
import React, { CSSProperties, forwardRef, isValidElement, Ref, useEffect, useState } from 'react';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import type { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';
import { GenericContext } from '../model/GenericContextModel';
import { SxProps, Stack } from '@mui/material';

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
    // Use flex: 1 + minHeight: 0 instead of height: '100%' so this div
    // fills exactly the remaining space in the Paper flex-column layout
    // (after DrawerHeader). This ensures only this div scrolls when content
    // overflows, preventing a competing scroll on the MUI Paper itself.
    // Without this, both the Paper and this div have overflow:auto and both
    // try to scroll, causing WindowScroller to track the wrong element and
    // breaking InfiniteLoader pagination inside drawers.
    flex: 1,
    minHeight: 0,
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
  variant?: DrawerVariant;
  context?: readonly (GenericContext | null)[] | null;
  header?: React.ReactElement;
  subHeader?: {
    right?: React.ReactElement[];
    left?: React.ReactElement[];
  };
  controlledDial?: DrawerControlledDialType;
  containerStyle?: CSSProperties;
  /**
   * Optional ref forwarded to the inner scrollable container div.
   * Used by components such as ListLinesContent to correctly bind
   * infinite-scroll detection to the drawer's scroll element rather
   * than the window, which prevents blank gaps when loading paginated
   * entity lists inside a drawer.
   */
  containerRef?: Ref<HTMLDivElement>;
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
  variant,
  context,
  header,
  subHeader,
  controlledDial,
  containerStyle,
  containerRef,
  disabled = false,
  size = 'large',
  disableBackdropClose = false,
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
        onClose={disableBackdropClose
          ? (_, reason) => {
              if (reason !== 'backdropClick') {
                handleClose();
              }
            }
          : handleClose}
        onClick={(e) => e.stopPropagation()}
        sx={{
          zIndex: 1202,
        }}
        slotProps={{
          paper: {
            ref,
            sx: {
              // Use height (not minHeight) so the Paper has a DEFINITE height.
              // With minHeight alone, CSS flex doesn't distribute available space
              // to flex children (flex:1 on .container doesn't work as expected),
              // so the container grew to match its content with no overflow/scroll.
              // With height:100vh the container is constrained to viewport minus
              // DrawerHeader, content overflow triggers the overflowY:auto scroll.
              height: '100vh',
              width: getDrawerWidth(size),
              position: 'fixed',
              // Use overflow: hidden (not auto) so the Paper itself never
              // scrolls. Scrolling is delegated to the inner .container div
              // which uses flex:1 to fill the remaining space. This removes
              // the dual-scroll issue that broke WindowScroller pagination.
              overflow: 'hidden',
              display: 'flex',
              flexDirection: 'column',
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
          ref={containerRef}
          className={classes.container}
          style={{
            ...containerStyle,
            backgroundColor: theme.palette.background.drawer,
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
