import Button from '@mui/material/Button';
import React, { useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import EnterpriseEditionAgreement from '@components/common/entreprise_edition/EnterpriseEditionAgreement';
import { RocketLaunchOutlined } from '@mui/icons-material';
import FeedbackCreation from '@components/cases/feedbacks/FeedbackCreation';
import classNames from 'classnames';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';
import type { Theme } from '../../../../components/Theme';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  button: {
    marginLeft: 20,
  },
});

const EnterpriseEditionButton = ({
  feature,
  inLine = false,
  disabled = false,
}: {
  feature?: string;
  inLine?: boolean
  disabled?: boolean
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const theme = useTheme<Theme>();

  const [openEnterpriseEditionConsent, setOpenEnterpriseEditionConsent] = useState(false);
  const [feedbackCreation, setFeedbackCreation] = useState(false);
  const {
    settings: { id: settingsId },
  } = useAuth();
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);
  return (
    <>
      <EnterpriseEditionAgreement
        open={openEnterpriseEditionConsent}
        onClose={() => setOpenEnterpriseEditionConsent(false)}
        settingsId={settingsId}
      />
      {isAdmin ? (
        <Button
          size="small"
          variant="outlined"
          color="ee"
          onClick={() => setOpenEnterpriseEditionConsent(true)}
          startIcon={<RocketLaunchOutlined style={{ color: disabled ? theme.palette.dangerZone.main : undefined }} />}
          disabled={disabled}
          style={{
            borderColor: disabled ? theme.palette.dangerZone.main : undefined,
          }}
          classes={{
            root: classNames({
              [classes.button]: !inLine,
            }),
          }}
        >
          {t_i18n('Enable Enterprise Edition')}
        </Button>
      ) : (
        <Button
          color="primary"
          variant="outlined"
          size="small"
          disabled={disabled}
          onClick={() => setFeedbackCreation(true)}
          classes={{ root: classes.button }}
        >
          {t_i18n('Create a feedback')}
        </Button>
      )}
      <FeedbackCreation
        openDrawer={feedbackCreation}
        handleCloseDrawer={() => setFeedbackCreation(false)}
        initialValue={{
          description: t_i18n(
            `I would like to use a EE feature ${
              feature ? `(${feature}) ` : ''
            }but I don't have EE activated.\nI would like to discuss with you about activating EE.`,
          ),
        }}
      />
    </>
  );
};

export default EnterpriseEditionButton;
