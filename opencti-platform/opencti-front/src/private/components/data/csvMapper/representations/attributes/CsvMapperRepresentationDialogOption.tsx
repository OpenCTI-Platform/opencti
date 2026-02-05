import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { CsvMapperRepresentationAttributeFormData } from '@components/data/csvMapper/representations/attributes/Attribute';
import { Badge } from '@mui/material';
import DialogActions from '@mui/material/DialogActions';
import { CogOutline } from 'mdi-material-ui';
import React, { FunctionComponent, ReactNode, useMemo } from 'react';
import { useFormatter } from '../../../../../../components/i18n';

interface CsvMapperRepresentationDialogOptionProps {
  children: ReactNode;
  configuration?: CsvMapperRepresentationAttributeFormData;
}

const CsvMapperRepresentationDialogOption: FunctionComponent<CsvMapperRepresentationDialogOptionProps> = ({ children, configuration }) => {
  const [open, setOpen] = React.useState(false);
  const { t_i18n } = useFormatter();
  const handleClickOpen = () => {
    setOpen(true);
  };
  const visible = useMemo(() => {
    const hasDefaultValues = (!!configuration?.default_values || configuration?.default_values === false) && JSON.stringify(configuration.default_values) !== '[]';
    const hasDatePattern = !!configuration?.pattern_date;
    const hasSeparator = !!configuration?.separator;
    return hasDefaultValues || hasDatePattern || hasSeparator;
  }, [configuration]);

  const handleClose = () => {
    setOpen(false);
  };
  return (
    <>
      <IconButton
        color="primary"
        aria-label={t_i18n('Settings')}
        onClick={handleClickOpen}
      >
        <Badge color="secondary" variant="dot" invisible={!visible}>
          <CogOutline />
        </Badge>
      </IconButton>
      <Dialog
        open={open}
        onClose={handleClose}
        aria-labelledby="csv-mapper-dialog-title"
        aria-describedby="Configure optional settings to the field"
        title={(
          <span id="csv-mapper-dialog-title">
            {t_i18n('Attribute mapping configuration')}
          </span>
        )}
      >
        {children}
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
