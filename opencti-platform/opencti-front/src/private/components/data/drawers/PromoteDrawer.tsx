import React from 'react';
import Alert from '@mui/material/Alert';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useTheme } from '@mui/styles';
import Checkbox from '@mui/material/Checkbox';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

type DrawerContainerPropsType = {
  isOpen: boolean;
  isOnlyStixCyberObservablesTypes: boolean;
  onClose: () => void;
  onSubmit: () => void;
  isContainer: boolean;
  promoteToContainer: boolean;
  togglePromoteToContainer: () => void;
};

const PromoteDrawer = ({ isOpen, onClose, isOnlyStixCyberObservablesTypes, onSubmit, isContainer, promoteToContainer, togglePromoteToContainer }: DrawerContainerPropsType) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const renderPromoteToContainerCheckBox = () => {
    if (!isContainer) return null;

    const type = isOnlyStixCyberObservablesTypes ? 'indicators' : 'observables';
    return (
      <div style={{ display: 'flex', alignItems: 'center', marginTop: 20 }}>
        <Checkbox edge="start" checked={promoteToContainer} onChange={togglePromoteToContainer} />
        <Typography>{t_i18n(`Add generated and existing ${type} in the container`)}</Typography>
      </div>
    );
  };

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
        {renderPromoteToContainerCheckBox()}
        <div style={{
          marginTop: 20,
          textAlign: 'right',
        }}
        >
          <Button
            sx={{ marginLeft: theme.spacing(2) }}
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
