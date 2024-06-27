import makeStyles from '@mui/styles/makeStyles';
import React, { useState } from 'react';
import FeedbackCreation from '@components/cases/feedbacks/FeedbackCreation';
import EnterpriseEditionAgreement from '@components/common/entreprise_edition/EnterpriseEditionAgreement';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    fontSize: 'xx-small',
    height: 14,
    display: 'inline-flex',
    justifyContent: 'center',
    alignItems: 'center',
    width: 21,
    margin: 'auto',
    marginLeft: 6,
    borderRadius: theme.borderRadius,
    border: `1px solid ${theme.palette.ee.main}`,
    color: theme.palette.ee.main,
    backgroundColor: theme.palette.ee.background,
    cursor: 'pointer',
  },
  containerFloating: {
    float: 'left',
    fontSize: 'xx-small',
    height: 14,
    display: 'inline-flex',
    justifyContent: 'center',
    alignItems: 'center',
    width: 21,
    margin: '2px 0 0 6px',
    borderRadius: theme.borderRadius,
    border: `1px solid ${theme.palette.ee.main}`,
    color: theme.palette.ee.main,
    backgroundColor: theme.palette.ee.background,
    cursor: 'pointer',
  },
}));

const EEChip = ({ feature, clickable = true, floating = false }: { feature?: string, clickable?: boolean, floating?: boolean }) => {
  const classes = useStyles();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const [displayDialog, setDisplayDialog] = useState(false);
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);
  const { settings: { id: settingsId } } = useAuth();
  return (!isEnterpriseEdition && (
    <>
      <div
        className={floating ? classes.containerFloating : classes.container}
        onClick={() => clickable && setDisplayDialog(true)}
      >
        EE
      </div>
      {isAdmin ? (
        <EnterpriseEditionAgreement
          open={displayDialog}
          onClose={() => setDisplayDialog(false)}
          settingsId={settingsId}
        />
      ) : (
        <FeedbackCreation
          openDrawer={displayDialog}
          handleCloseDrawer={() => setDisplayDialog(false)}
          initialValue={{
            description: t_i18n(`I would like to use a EE feature ${feature ? `(${feature}) ` : ''}but I don't have EE activated.\nI would like to discuss with you about activating EE.`),
          }}
        />
      )}
    </>
  ));
};

export default EEChip;
