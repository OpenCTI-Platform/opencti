import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

type DrawerContainerPropsType = {
  isOpen: boolean;
  isOnlyStixCyberObservablesTypes: boolean;
  onClose: () => void;
  onSubmit: () => void;
  isOnlyIndicator: boolean;
};

const PromoteDrawer = ({ isOpen, onClose, isOnlyStixCyberObservablesTypes, onSubmit, isOnlyIndicator }: DrawerContainerPropsType) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  return (
    <Drawer
      title={t_i18n('Observables and indicators conversion')}
      onClose={onClose}
      open={isOpen}
    >
      <>
        <div className={classes.container}>
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
                {isOnlyIndicator
                  ? t_i18n('This action will generate observables from the selected indicators.')
                  : t_i18n('This action will generate indicators from the selected observables.')
                }
              </Alert>
            </div>
          )}
          <div className={classes.buttons}>
            <Button
              variant="contained"
              color="secondary"
              onClick={onSubmit}
              classes={{ root: classes.button }}
            >
              {t_i18n('Generate')}
            </Button>
          </div>
        </div>
      </>
    </Drawer>
  );
};

export default PromoteDrawer;
