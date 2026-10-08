import { CloseOutlined } from '@mui/icons-material';
import { Box, DialogActionsProps, DialogContent, DialogContentProps, DialogTitle } from '@mui/material';
import MUIDialog, { DialogProps as MUIDialogProps } from '@mui/material/Dialog';
import { PaperProps } from '@mui/material/Paper';
import { ReactNode } from 'react';
import IconButton from '../button/IconButton';
import { SURFACE_LAYER, fdsLayerClass, layerInputVars } from '../../../utils/fdsLayer';

type MUIDialogSlotProps = NonNullable<MUIDialogProps['slotProps']>;
// MUI also accepts a function of the owner state for a slot; the paper slot is
// merged with this wrapper's own paper props, so only the object form is accepted.
type PaperSlotProps = Partial<PaperProps>;

type DialogProps = {
  title?: ReactNode;
  contentProps?: DialogContentProps;
  actionsProps?: DialogActionsProps;
  size?: DialogSize;
  showCloseButton?: boolean;
  slotProps?: Omit<MUIDialogSlotProps, 'paper'> & { paper?: PaperSlotProps };
} & Omit<MUIDialogProps, 'title' | 'slotProps'>;

type DialogSize = 'small' | 'medium' | 'large';

const DIALOG_SIZES: Record<DialogSize, string> = {
  small: '420px',
  medium: '640px',
  large: '960px',
};

const Dialog = ({
  title,
  children,
  contentProps,
  size = 'medium',
  showCloseButton = false,
  onClose,
  fullScreen = false,
  ...dialogProps
}: DialogProps) => {
  const callerPaperSlotProps = dialogProps.slotProps?.paper ?? {};
  return (
    <MUIDialog
      {...dialogProps}
      fullScreen={fullScreen}
      onClose={onClose}
      slotProps={{
        // Callers rely on other slots (e.g. `transition.onEntered` for focus
        // management), so their slotProps must be preserved, not replaced.
        ...dialogProps.slotProps,
        paper: {
          ...callerPaperSlotProps,
          className: [fdsLayerClass(SURFACE_LAYER), callerPaperSlotProps?.className]
            .filter(Boolean)
            .join(' '),
          sx: {
            ...layerInputVars,
            paddingTop: 3,
            paddingBottom: 3,
            ...callerPaperSlotProps?.sx,
          },
        },
      }}
      sx={{
        ...(!fullScreen && {
          '& .MuiDialog-paper': {
            maxWidth: DIALOG_SIZES[size],
            width: '100%',
          },
        }),

        ...dialogProps.sx,
      }}
    >
      {(title || showCloseButton) && (
        <DialogTitle sx={{
          paddingY: 0,
          paddingX: 3,
          mb: 2,
          display: 'flex',
          alignItems: 'center',
          justifyContent: showCloseButton && !title ? 'flex-end' : 'space-between',
        }}
        >
          {title && <Box component="span" sx={{ width: '100%' }}>{title}</Box>}
          {showCloseButton && onClose && (
            <IconButton
              aria-label="close"
              onClick={(event) => onClose?.(event, 'escapeKeyDown')}
              size="default"
            >
              <CloseOutlined fontSize="medium" />
            </IconButton>
          )}
        </DialogTitle>
      )}

      {/* This element scrolls, so a field flush with the edge loses the focus ring the
          library paints 4px outside it; `&&` because MUI's `.MuiDialogTitle-root + &`
          outranks a plain `sx`. See fds-migration/MIGRATION-DECISIONS.md#dialog-padding-keys
          `position: relative` keeps absolutely positioned descendants inside this scroller;
          otherwise they anchor to the (relative) paper and make it scroll too. */}
      <DialogContent {...contentProps} sx={{ px: 3, position: 'relative', '&&': { py: '4px', my: '-4px' } }}>
        {children}
      </DialogContent>
    </MUIDialog>
  );
};

export default Dialog;
