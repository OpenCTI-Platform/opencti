import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
// fds:keep-mui the library Tooltip is a compound API; this call site converts with the wider Tooltip wave
import { Tooltip, TooltipProps } from '@mui/material';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import { ReactElement, ReactNode, useContext, useEffect, useRef, useState } from 'react';
import { useFormatter } from '../../../../components/i18n';
import useAI from '../../../../utils/hooks/useAI';
import useAuth from '../../../../utils/hooks/useAuth';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import EnterpriseEditionAgreement from './EnterpriseEditionAgreement';
import { onActivationKey } from '../../../../utils/domEvent';
import EERequestContext, { EERequest } from './EERequestContext';

const EETooltipComponent = ({ children, ...tooltipProps }: TooltipProps) => {
  return (
    <Tooltip
      {...tooltipProps}
      slotProps={{
        popper: {
          sx: {
            textTransform: 'none',
          },
        },
      }}
    >
      {children}
    </Tooltip>
  );
};

const MessageDialog = ({ open, onClose, title, message }: { open: boolean; onClose: () => void; title: string; message: string }) => {
  const { t_i18n } = useFormatter();
  return (
    <Dialog open={open} onClose={onClose} size="small" title={title}>
      <DialogContent>{message}</DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t_i18n('Close')}</Button>
      </DialogActions>
    </Dialog>
  );
};

// Anything a keyboard user can reach with Tab
const TABBABLE_SELECTOR = 'a[href], button, input, select, textarea, summary, iframe, [tabindex], [contenteditable="true"]';

/**
 * The gate shown instead of a feature the platform cannot run yet: one button that opens
 * `onActivate` instead of whatever the wrapped content would do. The content stays visible
 * and clickable (its clicks are intercepted), but is hidden from assistive tech and out of
 * the tab order at any depth, so the gate is the only control for it. An `inert` content
 * would do both, but its clicks would then fall through to the gate's parent whenever the
 * content is a block.
 */
// `label` names the gate: its content is hidden from assistive tech, so cannot name it
const EEGate = ({ title, label, onActivate, children }: { title?: string; label: string; onActivate: () => void; children: ReactNode }) => {
  const contentRef = useRef<HTMLSpanElement>(null);

  // Watched, not set once: the content may render or re-enable a control later
  useEffect(() => {
    const content = contentRef.current;
    if (!content) return undefined;
    const removeFromTabOrder = () => {
      content.querySelectorAll<HTMLElement>(TABBABLE_SELECTOR).forEach((element) => {
        if (element.getAttribute('tabindex') !== '-1') element.setAttribute('tabindex', '-1');
      });
    };
    removeFromTabOrder();
    const observer = new MutationObserver(removeFromTabOrder);
    observer.observe(content, { subtree: true, childList: true, attributes: true, attributeFilter: ['tabindex', 'disabled', 'href', 'contenteditable'] });
    return () => observer.disconnect();
  }, []);

  return (
    <EETooltipComponent title={title}>
      <span
        role="button"
        tabIndex={0}
        aria-label={label}
        onClickCapture={(e) => {
          e.preventDefault();
          e.stopPropagation();
          onActivate();
        }}
        onKeyDownCapture={onActivationKey((e) => {
          e.stopPropagation();
          onActivate();
        })}
      >
        <span ref={contentRef} aria-hidden>{children}</span>
      </span>
    </EETooltipComponent>
  );
};

export interface EETooltipBaseProps {
  children: ReactElement;
  title?: string;
  forAi?: boolean;
  // What a non-admin gets when activating the gate without Enterprise Edition. Defaults to
  // the one the app provides through EERequestContext (the feedback form), then to a dialog
  // sending them to their administrator when nothing is provided (isolated tests).
  renderNonAdminRequest?: EERequest;
}

/**
 * The Enterprise Edition gate without a static import of the feedback form. Use EETooltip,
 * unless the gated control is reachable from the feedback form itself (the AI button of the
 * text fields).
 */
const EETooltipBase = ({
  children,
  title,
  forAi,
  renderNonAdminRequest,
}: EETooltipBaseProps) => {
  const { t_i18n } = useFormatter();
  const providedRequest = useContext(EERequestContext);
  const nonAdminRequest = renderNonAdminRequest ?? providedRequest;
  const [requestOpen, setRequestOpen] = useState(false);
  const [openConfigAI, setOpenConfigAI] = useState(false);
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const { enabled, configured } = useAI();
  const {
    settings: { id: settingsId },
  } = useAuth();

  if (isEnterpriseEdition && (!forAi || (forAi && enabled && configured))) {
    return (
      <EETooltipComponent
        title={title ? t_i18n(title) : undefined}
      >
        {children}
      </EETooltipComponent>
    );
  }

  if (isEnterpriseEdition && forAi && !configured) {
    return (
      <>
        <EEGate
          title={title ? t_i18n(title) : undefined}
          label={title ? t_i18n(title) : t_i18n('Enable AI powered platform')}
          onActivate={() => setOpenConfigAI(true)}
        >
          {children}
        </EEGate>
        <MessageDialog
          open={openConfigAI}
          onClose={() => setOpenConfigAI(false)}
          title={t_i18n('Enable AI powered platform')}
          message={t_i18n('The token is missing in your platform configuration, please ask your Filigran representative to provide you with it or with on-premise deployment instructions. You can open a support ticket to do so.')}
        />
      </>
    );
  }
  return (
    <>
      <EEGate
        title={title ? t_i18n(title) : undefined}
        label={title ? t_i18n(title) : t_i18n('Enterprise Edition')}
        onActivate={() => setRequestOpen(true)}
      >
        {children}
      </EEGate>
      {isAdmin ? (
        <EnterpriseEditionAgreement
          open={requestOpen}
          onClose={() => setRequestOpen(false)}
          settingsId={settingsId}
        />
      ) : nonAdminRequest ? nonAdminRequest(requestOpen, () => setRequestOpen(false), title) : (
        <MessageDialog
          open={requestOpen}
          onClose={() => setRequestOpen(false)}
          title={t_i18n('Enterprise Edition')}
          message={t_i18n('Please ask your administrator to enable the Enterprise Edition.')}
        />
      )}
    </>
  );
};

export default EETooltipBase;
