import Button from '@common/button/Button';
import type { ButtonSize } from '@common/button/Button.types';
import React, { CSSProperties, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import EnterpriseEditionAgreement from '@components/common/entreprise_edition/EnterpriseEditionAgreement';
import EEChip from '@components/common/entreprise_edition/EEChip';
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

/**
 * Composition: the EE badge is a sibling at a 4px gap to the button's right, so
 * each keeps its own box. The button owns the action, so the badge stays inert.
 *
 * NOTE: the "never INSIDE a button" rule this comment used to state as doctrine
 * was REVERSED by the designer during the night-2 pass -- the Ariane IA button
 * now carries its chip in the button's trailing slot, with `clickable={false}`
 * making that legal. This site was not part of that instruction and is left as
 * a sibling on purpose; it is the other consumer of the reversed rule and the
 * one to revisit if the inside placement is meant to be general.
 */
const eeRow: CSSProperties = { display: 'inline-flex', alignItems: 'center', gap: 4 };

const EnterpriseEditionButton = ({
  feature,
  inLine = false,
  disabled = false,
  withEEChip = false,
  title = 'Manage your Enterprise Edition license',
  size = 'small',
}: {
  feature?: string;
  inLine?: boolean;
  disabled?: boolean;
  withEEChip?: boolean;
  title?: string;
  size?: ButtonSize;
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
      <span style={eeRow}>
        {isAdmin ? (
          <Button
            size={size}
            variant="secondary"
            // color="ee"
            onClick={() => setOpenEnterpriseEditionConsent(true)}
            startIcon={<RocketLaunchOutlined style={{ color: disabled ? theme.palette.dangerZone.main : undefined }} />}
            disabled={disabled}
            classes={{
              root: classNames({
                [classes.button]: !inLine,
              }),
            }}
          >
            {t_i18n(title)}
          </Button>
        ) : (
          <Button
            variant="secondary"
            size={size}
            disabled={disabled}
            onClick={() => setFeedbackCreation(true)}
            classes={{ root: classes.button }}
          >
            {t_i18n('Create a feedback')}
          </Button>
        )}
        {withEEChip && (
          <EEChip feature={feature} clickable={false} style={{ marginInlineStart: 0 }} />
        )}
      </span>
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
