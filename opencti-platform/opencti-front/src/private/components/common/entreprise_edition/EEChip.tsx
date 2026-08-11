import { Chip } from '@filigran/design-system';
import React, { CSSProperties, MouseEvent, useState } from 'react';
import FeedbackCreation from '@components/cases/feedbacks/FeedbackCreation';
import EnterpriseEditionAgreement from '@components/common/entreprise_edition/EnterpriseEditionAgreement';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';
import { useTheme } from '@mui/material/styles';

interface EEChipProps {
  feature?: string;
  clickable?: boolean;
  floating?: boolean;
  /** Opt in to the library `Chip`; every other call site keeps the legacy marker. */
  libraryChip?: boolean;
}

const EEChip = React.forwardRef<HTMLDivElement, EEChipProps>((
  { feature, clickable = true, floating = false, libraryChip = false },
  ref,
) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [displayDialog, setDisplayDialog] = useState(false);
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);
  const { settings: { id: settingsId } } = useAuth();

  const onClick = (e: MouseEvent<HTMLDivElement>) => {
    e.stopPropagation();
    e.preventDefault();
    return clickable && setDisplayDialog(true);
  };
  const divStyle: CSSProperties = floating
    ? {
        float: 'left',
        fontSize: 'xx-small',
        height: 18,
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
      }
    : {
        fontSize: 'xx-small',
        height: 18,
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
      };

  return (!isEnterpriseEdition && (
    <>
      {libraryChip ? (
        // FDS-WORKAROUND #21: decorative only, a clickable Chip renders a nested <button> — see fds-migration/LIBRARY-FEEDBACK.md #21
        <Chip label="EE" tone="tonic" />
      ) : (
        <div
          ref={ref}
          style={divStyle}
          onClick={(e) => onClick(e)}
        >
          EE
        </div>
      )}
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
