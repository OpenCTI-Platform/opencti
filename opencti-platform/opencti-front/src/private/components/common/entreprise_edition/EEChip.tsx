import { Chip } from '@filigran/design-system';
import React, { CSSProperties, MouseEvent, useState } from 'react';
import FeedbackCreation from '@components/cases/feedbacks/FeedbackCreation';
import EnterpriseEditionAgreement from '@components/common/entreprise_edition/EnterpriseEditionAgreement';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';

/** Matches the legacy marker's `marginLeft: 6`; a call site may override it. */
const EE_CHIP_GAP: CSSProperties = { marginInlineStart: 6 };

interface EEChipProps {
  feature?: string;
  /**
   * Default `true`: the chip renders as a real `<button>` that opens the EE
   * dialog. The legacy marker was a `<div>` carrying an `onClick` and no role,
   * so it was unreachable by keyboard -- the conversion fixes that on its own.
   *
   * `false` is for the three sites that sit INSIDE a button, where the
   * surrounding control owns the click and a nested button would be invalid.
   */
  clickable?: boolean;
  style?: CSSProperties;
}

const EEChip = React.forwardRef<HTMLElement, EEChipProps>((
  { feature, clickable = true, style },
  ref,
) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const [displayDialog, setDisplayDialog] = useState(false);
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);
  const { settings: { id: settingsId } } = useAuth();

  const onClick = (e: MouseEvent<HTMLElement>) => {
    e.stopPropagation();
    e.preventDefault();
    setDisplayDialog(true);
  };

  return (!isEnterpriseEdition && (
    <>
      <Chip
        ref={ref}
        label="EE"
        severity="ee"
        onClick={clickable ? onClick : undefined}
        style={{ ...EE_CHIP_GAP, ...style }}
      />
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
});

EEChip.displayName = 'EEChip';

export default EEChip;
