import makeStyles from '@mui/styles/makeStyles';
import React, { useState } from 'react';
import FeedbackCreation from '@components/cases/feedbacks/FeedbackCreation';
import EnterpriseEditionAgreement from '@components/common/entreprise_edition/EnterpriseEditionAgreement';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';

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
}));

const EEChip = ({ feature, clickable = true }: { feature?: string, clickable?: boolean }) => {
  const classes = useStyles();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t } = useFormatter();

  const [displayDialog, setDisplayDialog] = useState(false);
  const isAdmin = useGranted([SETTINGS]);
  const { settings: { id: settingsId } } = useAuth();

  return (!isEnterpriseEdition && (
    <>
      <div
        className={classes.container}
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
            description: t(`I would like to use a EE feature ${feature ? `(${feature}) ` : ''}but I don't have EE activated.\nI would like to discuss with you about activating EE.`),
          }}
        />
      )}
    </>
  ));
};

export default EEChip;
