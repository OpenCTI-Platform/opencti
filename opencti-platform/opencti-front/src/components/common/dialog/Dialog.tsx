import { CloseOutlined } from '@mui/icons-material';
import { Box, DialogActionsProps, DialogContent, DialogContentProps, DialogTitle } from '@mui/material';
import MUIDialog, { DialogProps as MUIDialogProps } from '@mui/material/Dialog';
import { ReactNode } from 'react';
import IconButton from '../button/IconButton';
import { SURFACE_LAYER, fdsLayerClass, layerInputVars } from '../../../utils/fdsLayer';

type DialogProps = {
  title?: ReactNode;
  contentProps?: DialogContentProps;
  actionsProps?: DialogActionsProps;
  size?: DialogSize;
  showCloseButton?: boolean;
} & Omit<MUIDialogProps, 'title'>;

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
  return (
    <MUIDialog
      {...dialogProps}
      fullScreen={fullScreen}
      onClose={onClose}
      slotProps={{
        paper: {
          // A dialog is a layer-2 surface: the class re-declares the elevation aliases, `layerInputVars` carries
          // the three input backgrounds the library's own .layer-N blocks forget.
          className: fdsLayerClass(SURFACE_LAYER),
          sx: {
            ...layerInputVars,
            paddingTop: 3,
            // Symmetric with paddingTop.
            paddingBottom: 3,
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
          outranks a plain `sx`. See fds-migration/MIGRATION-DECISIONS.md#dialog-padding-keys */}
      <DialogContent {...contentProps} sx={{ px: 3, '&&': { py: '4px', my: '-4px' } }}>
        {children}
      </DialogContent>
    </MUIDialog>
  );
};

export default Dialog;
