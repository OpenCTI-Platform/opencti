import { CloseOutlined } from '@mui/icons-material';
import { Box, DialogActionsProps, DialogContent, DialogContentProps, DialogTitle } from '@mui/material';
import MUIDialog, { DialogProps as MUIDialogProps } from '@mui/material/Dialog';
import { ReactNode } from 'react';
import IconButton from '../button/IconButton';

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
      onClick={(e) => e.stopPropagation()}
      slotProps={{
        paper: {
          sx: {
            paddingTop: 3,
            // Symmetric with paddingTop. The `py: 0` below is deliberate -- the
            // PAPER owns the outer gutter, not DialogContent -- but the paper
            // had no bottom counterpart, so once the padding typo was fixed the
            // content sat flush against the edge. 145 of the 171 consumers end
            // their children with a DialogActions row, so that landed under a
            // button nearly everywhere.
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

      {/* `py`/`px`, not `pY`/`pX`. MUI's system keys are lower-case, so the
          previous spelling was dropped silently and every dialog fell back to
          DialogContent's own `padding: 20px 24px`. Net effect of the fix,
          measured against the installed MUI source: horizontal is unchanged
          (24px either way) and the top was already 0 for a titled dialog
          (`.MuiDialogTitle-root + & { paddingTop: 0 }`), so what actually
          changes is the BOTTOM -- 20px to 0. A dialog with no title loses its
          20px top as well. */}
      <DialogContent {...contentProps} sx={{ py: 0, px: 3 }}>
        {children}
      </DialogContent>
    </MUIDialog>
  );
};

export default Dialog;
