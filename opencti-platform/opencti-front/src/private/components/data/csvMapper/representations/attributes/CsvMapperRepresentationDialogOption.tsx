import React, { FunctionComponent, ReactNode } from 'react';
import Dialog from '@mui/material/Dialog';
import Button from '@mui/material/Button';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import { CogOutline } from 'mdi-material-ui';
import IconButton from '@mui/material/IconButton';
import { AttributeWithMetadata } from '@components/data/csvMapper/representations/attributes/Attribute';
import { useFormatter } from '../../../../../../components/i18n';

interface CsvMapperRepresentationDialogOptionProps {
  attribute: AttributeWithMetadata
  children: ReactNode
}

const CsvMapperRepresentationDialogOption: FunctionComponent<CsvMapperRepresentationDialogOptionProps> = ({ attribute, children }) => {
  const [open, setOpen] = React.useState(false);
  const { t_i18n } = useFormatter();
  const handleClickOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };
  return (
    <>
      <IconButton
        color="primary"
        aria-label={t_i18n('Settings')}
        onClick={handleClickOpen}
        size="large"
        disabled={!attribute.column?.column_name}
      >
        <CogOutline/>
      </IconButton>
      <Dialog
        open={open}
        onClose={handleClose}
        aria-labelledby="csv-mapper-dialog-title"
        aria-describedby="Configure optional settings to the field"
      >
        <DialogTitle id="csv-mapper-dialog-title">
          {t_i18n('Attribute mapping configuration')}
        </DialogTitle>
        <DialogContent>
          {children}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose} autoFocus>
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default CsvMapperRepresentationDialogOption;
