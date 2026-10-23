import React from 'react';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import { useFormatter } from '../../../../components/i18n';

interface RuleRescanDrawerProps {
  open: boolean;
  onClose: () => void;
  onLaunch: () => void;
}

const RuleRescanDrawer = ({ open, onClose, onLaunch }: RuleRescanDrawerProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Drawer
      title={t_i18n('Rule entity rescan')}
      open={open}
      onClose={onClose}
    >
      <div>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Selected rules')}
        </Typography>
        <Alert severity="warning" style={{ marginTop: 20 }}>
          {t_i18n('Element will be rescan with all compatible activated rules')}
        </Alert>
        <FormButtonContainer>
          <Button onClick={onLaunch}>
            {t_i18n('Rescan')}
          </Button>
        </FormButtonContainer>
      </div>
    </Drawer>
  );
};

export default RuleRescanDrawer;
