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
      slotProps={{
        paper: {
          sx: {
            paddingTop: 3,
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

      <DialogContent {...contentProps} sx={{ pY: 0, pX: 3 }}>
        {children}
      </DialogContent>
    </MUIDialog>
  );
};

export default Dialog;
