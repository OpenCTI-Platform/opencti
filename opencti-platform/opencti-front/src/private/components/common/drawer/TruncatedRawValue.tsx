import React, { FunctionComponent, useState } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import Tooltip from '@mui/material/Tooltip';
import Dialog from '@mui/material/Dialog';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';

const TruncatedRawValue: FunctionComponent<{ value: string }> = ({ value }) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const theme = useTheme<Theme>();

  if (!value) return <pre style={{ margin: 0 }}>-</pre>;
  if (value.length <= 50) {
    return (
      <pre style={{
        fontFamily: 'Consolas, monaco, monospace',
        margin: 0,
        color: theme.palette.text?.secondary,
      }}
      >
        {value}
      </pre>
    );
  }

  return (
    <>
      <Tooltip title={t_i18n('Click to view full value')}>
        <pre
          onClick={() => setOpen(true)}
          style={{
            fontFamily: 'Consolas, monaco, monospace',
            cursor: 'pointer',
            margin: 0,
            color: theme.palette.text?.secondary,
          }}
        >
          {value.substring(0, 50)}...
        </pre>
      </Tooltip>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        maxWidth="md"
        fullWidth={true}
      >
        <DialogTitle>{t_i18n('Raw value')}</DialogTitle>
        <DialogContent>
          <pre>{value}</pre>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)} color="primary">
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default TruncatedRawValue;
