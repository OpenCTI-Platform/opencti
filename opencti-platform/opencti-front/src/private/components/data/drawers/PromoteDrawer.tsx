import React from 'react';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

type DrawerContainerPropsType = {
  isOpen: boolean;
  isOnlyStixCyberObservablesTypes: boolean;
  onClose: () => void;
  onSubmit: () => void;
};

const PromoteDrawer = ({ isOpen, onClose, isOnlyStixCyberObservablesTypes, onSubmit }: DrawerContainerPropsType) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  return (
    <Drawer
      title={t_i18n('Observables and indicators conversion')}
      onClose={onClose}
      open={isOpen}
    >

      <div style={{ padding: '10px 20px 20px 20px' }}>
        {isOnlyStixCyberObservablesTypes ? (
          <div>
            <Alert severity="warning" style={{ marginTop: 20 }}>
              {t_i18n(
                'This action will generate STIX patterns indicators from the selected observables.',
              )}
            </Alert>
          </div>
        ) : (
          <div>
            <Alert severity="warning" style={{ marginTop: 20 }}>
              {t_i18n('This action will generate observables from the selected indicators.')}
            </Alert>
          </div>
        )}
        <div style={{
          marginTop: 20,
          textAlign: 'right',
        }}
        >
          <Button
            sx={{ marginLeft: theme.spacing(2) }}
            variant="contained"
            color="secondary"
            onClick={onSubmit}
          >
            {t_i18n('Generate')}
          </Button>
        </div>
      </div>
    </Drawer>
  );
};

export default PromoteDrawer;
