import React, { Suspense, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link, useLocation, useNavigate } from 'react-router';
import { useTheme } from '@mui/styles';
import { CheckCircleOutlined, ErrorOutlineOutlined, ManageSearchOutlined, WarningAmberOutlined } from '@mui/icons-material';
import { Alert, Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogTitle, Spinner, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '../../../components/common/card/Card';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { MESSAGING$ } from '../../../relay/environment';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { PATH_HUNT } from '../common/routes/paths';
import { HuntStatusChip } from './HuntChips';
import HuntRunStart from './runs/HuntRunStart';
import HuntTranslationPreview from './HuntTranslationPreview';
import { useHuntScheduleText } from './HuntSchedulePreview';
import {
  HUNT_READINESS_READ_ONLY_TEMPLATES,
  HUNT_STATUS_MEANINGS,
  HUNT_STATUS_MEANINGS_READ_ONLY,
  HUNT_STATUSES,
  huntDraftWorkspacePath,
  huntStatusLabel,
  type HuntStatusValue,
} from './hunt-utils';
import { mutationErrorMessage, notifyPayloadErrors, payloadErrorsMessage, useDialogMutation } from './hunt-mutation-utils';
import { HuntStatusHeader_hunt$data, HuntStatusHeader_hunt$key } from './__generated__/HuntStatusHeader_hunt.graphql';
import { HuntStatusHeaderStatusMutation } from './__generated__/HuntStatusHeaderStatusMutation.graphql';
import { layerInputVars } from '../../../utils/fdsLayer';

export const HUNT_CONNECTORS_DOCUMENTATION_URL = 'https://docs.opencti.io/latest/usage/hunt-connectors/';
export const HUNT_CONNECTORS_PATH = '/dashboard/data/ingestion/connectors';

const huntStatusHeaderFragment = graphql`
  fragment HuntStatusHeader_hunt on Hunt {
    id
    hunt_status
    hunt_type
    time_window_hours
    scopePlatforms {
      id
      name
    }
    readiness {
      ready
      items {
        key
        status
        template
        values {
          name
          value
        }
        message
      }
    }
  }
`;

export const huntStatusHeaderStatusMutation = graphql`
  mutation HuntStatusHeaderStatusMutation($id: ID!, $input: [EditInput]!) {
    huntFieldPatch(id: $id, input: $input) {
      id
      hunt_status
      next_run_at
      ...HuntStatusHeader_hunt
      ...HuntDetails_hunt
    }
  }
`;

type ReadinessItem = HuntStatusHeader_hunt$data['readiness']['items'][number];

/** The status a hunt moves to with the primary action of its status, and the label of that action. */
export const huntPrimaryStatusAction = (status: string): { to: HuntStatusValue; label: string } | null => {
  switch (status) {
    case 'draft': return { to: 'active', label: 'Activate' };
    case 'active': return { to: 'paused', label: 'Pause' };
    case 'paused': return { to: 'active', label: 'Resume' };
    case 'retired': return { to: 'draft', label: 'Reopen as draft' };
    default: return null;
  }
};

/** The sentence of a readiness item in the language of the user, with the values the platform sent. */
export const useReadinessSentence = () => {
  const { t_i18n } = useFormatter();
  const scheduleText = useHuntScheduleText();
  return (item: Pick<ReadinessItem, 'key' | 'template' | 'values'>, canEdit = true) => {
    const values: Record<string, string> = Object.fromEntries(item.values.map(({ name, value }) => [name, value]));
    if (item.key === 'schedule' && values.schedule) {
      values.schedule = scheduleText(values.schedule);
    }
    const template = canEdit ? item.template : (HUNT_READINESS_READ_ONLY_TEMPLATES[item.template] ?? item.template);
    return t_i18n(template, { values });
  };
};

interface ReadinessActionProps {
  item: ReadinessItem;
  huntId: string;
  canEdit: boolean;
}

/** Where to fix an unmet or warning item, one link. */
const ReadinessAction = ({ item, huntId, canEdit }: ReadinessActionProps) => {
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const navigate = useNavigate();
  const draftContext = useDraftContext();
  const linkProps = { variant: 'tertiary' as const, size: 'small' as const, component: Link };
  switch (item.key) {
    case 'logic':
      return <Button {...linkProps} to={`${PATH_HUNT(huntId)}/logic`} data-testid="hunt-readiness-open-logic">{t_i18n('Open the logic')}</Button>;
    case 'connector':
      return (
        <>
          <Button {...linkProps} to={HUNT_CONNECTORS_PATH} data-testid="hunt-readiness-open-connectors">{t_i18n('Open the hunt connectors')}</Button>
          <Button variant="tertiary" size="small" href={HUNT_CONNECTORS_DOCUMENTATION_URL} target="_blank" rel="noopener noreferrer">
            {t_i18n('How to deploy a hunt connector')}
          </Button>
        </>
      );
    case 'schedule':
    case 'scope':
      return canEdit ? (
        <Button
          variant="tertiary"
          size="small"
          onClick={() => navigate(location.pathname, { state: { openHuntEdition: true } })}
          data-testid={`hunt-readiness-edit-${item.key}`}
        >
          {item.key === 'schedule' ? t_i18n('Edit the schedule') : t_i18n('Edit the scope')}
        </Button>
      ) : null;
    case 'draft':
      return draftContext ? <Button {...linkProps} to={huntDraftWorkspacePath(draftContext.id)}>{t_i18n('Open the draft')}</Button> : null;
    default:
      return null;
  }
};

const ReadinessIcon = ({ status }: { status: string }) => {
  const theme = useTheme<Theme>();
  if (status === 'met') return <CheckCircleOutlined fontSize="small" style={{ color: theme.palette.success.main }} aria-hidden />;
  if (status === 'warning') return <WarningAmberOutlined fontSize="small" style={{ color: theme.palette.warn.main }} aria-hidden />;
  return <ErrorOutlineOutlined fontSize="small" style={{ color: theme.palette.error.main }} aria-hidden />;
};

interface HuntReadinessChecklistProps {
  huntId: string;
  items: ReadonlyArray<ReadinessItem>;
  canEdit?: boolean;
}

/** What a hunt needs to run, item by item, each unmet one with the place to fix it. */
export const HuntReadinessChecklist = ({ huntId, items, canEdit = true }: HuntReadinessChecklistProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const sentence = useReadinessSentence();
  const statusLabel = (status: string) => {
    if (status === 'met') return t_i18n('Ready');
    if (status === 'warning') return t_i18n('Attention');
    return t_i18n('To complete');
  };
  return (
    <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: theme.spacing(0.75) }} data-testid="hunt-readiness">
      {items.map((item) => (
        <li
          key={`${item.key}-${item.template}`}
          style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}
          data-testid={`hunt-readiness-${item.key}`}
          data-status={item.status}
        >
          <ReadinessIcon status={item.status} />
          <span className="sr-only" style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' }}>{statusLabel(item.status)}</span>
          <Text variant="content-compact">{sentence(item, canEdit)}</Text>
          {item.status !== 'met' && <ReadinessAction item={item} huntId={huntId} canEdit={canEdit} />}
        </li>
      ))}
    </ul>
  );
};

interface HuntStatusHeaderProps {
  data: HuntStatusHeader_hunt$key;
  // Whether the user may change the hunt: its actions are hidden otherwise, as the edit control of the entity header
  canEdit?: boolean;
}

/**
 * The status of a hunt on every tab of its page: what the status means, the primary action of that status, Run now,
 * the query preview, and the readiness checklist; an action that cannot be taken says why next to it.
 */
const HuntStatusHeader = ({ data, canEdit = true }: HuntStatusHeaderProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const hunt = useFragment(huntStatusHeaderFragment, data);
  const [commit, inFlight] = useApiMutation<HuntStatusHeaderStatusMutation>(huntStatusHeaderStatusMutation);
  const [commitRetire, retiring] = useDialogMutation<HuntStatusHeaderStatusMutation>(huntStatusHeaderStatusMutation);
  const [showStatuses, setShowStatuses] = useState(hunt.hunt_status === 'draft');
  const [showChecklist, setShowChecklist] = useState(!hunt.readiness.ready || hunt.hunt_status !== 'active');
  const [confirmRetire, setConfirmRetire] = useState(false);
  const [retireError, setRetireError] = useState<string | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const status = hunt.hunt_status as HuntStatusValue;
  const primary = huntPrimaryStatusAction(status);
  const unmet = hunt.readiness.items.filter((item) => item.status === 'unmet');
  const warnings = hunt.readiness.items.filter((item) => item.status === 'warning');
  const needsReadiness = primary?.to === 'active';
  const primaryBlocked = needsReadiness && unmet.length > 0;
  const scopePlatformIds = (hunt.scopePlatforms ?? []).map((platform) => platform.id);
  const meanings = canEdit ? HUNT_STATUS_MEANINGS : HUNT_STATUS_MEANINGS_READ_ONLY;

  const apply = (to: HuntStatusValue) => {
    commit({
      variables: { id: hunt.id, input: [{ key: 'hunt_status', value: [to] }] },
      onCompleted: (_, errors) => {
        if (notifyPayloadErrors(errors)) return;
        if (to === 'active') {
          MESSAGING$.notifySuccess(t_i18n('The hunt is active'));
        }
      },
    });
  };

  const openRetire = (next: boolean) => {
    setRetireError(null);
    setConfirmRetire(next);
  };
  const retire = () => {
    setRetireError(null);
    commitRetire({
      variables: { id: hunt.id, input: [{ key: 'hunt_status', value: ['retired'] }] },
      onCompleted: (_, errors) => {
        const errorMessage = payloadErrorsMessage(errors);
        if (errorMessage) {
          setRetireError(errorMessage);
          return;
        }
        setConfirmRetire(false);
      },
      onError: (error) => setRetireError(mutationErrorMessage(error, t_i18n('The hunt could not be retired'))),
    });
  };

  let readinessSummary: string;
  if (unmet.length > 0) {
    readinessSummary = unmet.length === 1
      ? t_i18n('1 item to complete before the hunt can run')
      : t_i18n('{count} items to complete before the hunt can run', { values: { count: String(unmet.length) } });
  } else if (warnings.length > 0) {
    readinessSummary = warnings.length === 1
      ? t_i18n('Ready to run, 1 point needs attention')
      : t_i18n('Ready to run, {count} points need attention', { values: { count: String(warnings.length) } });
  } else {
    readinessSummary = t_i18n('Ready to run');
  }

  return (
    <div style={{ marginBottom: theme.spacing(2) }} data-testid="hunt-status-header">
      <Card>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: theme.spacing(2), flexWrap: 'wrap' }}>
          <div style={{ minWidth: 280, flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
              <HuntStatusChip value={status} />
              <Text variant="content-compact" data-testid="hunt-status-meaning">{t_i18n(meanings[status] ?? '')}</Text>
              <Button variant="tertiary" size="small" aria-expanded={showStatuses} onClick={() => setShowStatuses(!showStatuses)} data-testid="hunt-status-model-toggle">
                {showStatuses ? t_i18n('Hide the statuses') : t_i18n('How statuses work')}
              </Button>
            </div>
            {showStatuses && (
              <dl style={{ margin: `${theme.spacing(1)} 0 0 0`, display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: `${theme.spacing(0.5)} ${theme.spacing(1.5)}` }} data-testid="hunt-status-model">
                {HUNT_STATUSES.map((value) => (
                  <React.Fragment key={value}>
                    <dt><Text variant={value === status ? 'content-compact-bold' : 'content-compact'}>{t_i18n(huntStatusLabel(value))}</Text></dt>
                    <dd style={{ margin: 0 }}><Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{t_i18n(meanings[value])}</Text></dd>
                  </React.Fragment>
                ))}
              </dl>
            )}
          </div>
          <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={canEdit}>
            <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap', justifyContent: 'flex-end' }}>
              {status !== 'retired' && (
                <Button variant="secondary" onClick={() => openRetire(true)} disabled={inFlight} data-testid="hunt-status-to-retired">
                  {t_i18n('Retire')}
                </Button>
              )}
              <Button variant="secondary" startIcon={<ManageSearchOutlined fontSize="small" />} onClick={() => setPreviewing(true)} data-testid="hunt-query-preview-open">
                {t_i18n('Preview the query')}
              </Button>
              <HuntRunStart hunt={hunt} secondary />
              {primary && (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: theme.spacing(1) }}>
                  <Button
                    variant={primary.to === 'active' ? 'primary' : 'secondary'}
                    disabled={inFlight || primaryBlocked}
                    onClick={() => apply(primary.to)}
                    aria-describedby={primaryBlocked ? 'hunt-primary-blocked-reason' : undefined}
                    data-testid={`hunt-status-to-${primary.to}`}
                  >
                    {t_i18n(primary.label)}
                  </Button>
                  {primaryBlocked && (
                    <Text id="hunt-primary-blocked-reason" variant="content-caption" style={{ color: theme.palette.error.main }} data-testid="hunt-primary-blocked-reason">
                      {unmet.length === 1 ? t_i18n('1 item to complete') : t_i18n('{count} items to complete', { values: { count: String(unmet.length) } })}
                    </Text>
                  )}
                </span>
              )}
            </div>
          </Security>
        </div>
        <div style={{ marginTop: theme.spacing(1.5), borderTop: `1px solid ${theme.palette.divider}`, paddingTop: theme.spacing(1.5) }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
            <ReadinessIcon status={unmet.length > 0 ? 'unmet' : (warnings.length > 0 ? 'warning' : 'met')} />
            <Text variant="content-compact-bold" data-testid="hunt-readiness-summary">{readinessSummary}</Text>
            <Button variant="tertiary" size="small" aria-expanded={showChecklist} onClick={() => setShowChecklist(!showChecklist)} data-testid="hunt-readiness-toggle">
              {showChecklist ? t_i18n('Hide the checklist') : t_i18n('Show the checklist')}
            </Button>
          </div>
          {showChecklist && (
            <div style={{ marginTop: theme.spacing(1), marginLeft: theme.spacing(3.5) }}>
              <HuntReadinessChecklist huntId={hunt.id} items={hunt.readiness.items} canEdit={canEdit} />
            </div>
          )}
        </div>
      </Card>
      <Dialog open={confirmRetire} onOpenChange={openRetire}>
        <DialogContent size="sm" data-testid="hunt-status-retire-dialog">
          <DialogTitle>{t_i18n('Retire this hunt?')}</DialogTitle>
          <DialogDescription>{t_i18n(HUNT_STATUS_MEANINGS.retired)}</DialogDescription>
          {retireError && (
            <DialogBody>
              <div role="alert">
                <Alert severity="error" title={t_i18n('The hunt could not be retired')} description={retireError} data-testid="hunt-status-retire-error" />
              </div>
            </DialogBody>
          )}
          <DialogFooter>
            <Button variant="secondary" onClick={() => openRetire(false)}>{t_i18n('Cancel')}</Button>
            <Button onClick={retire} disabled={retiring} data-testid="hunt-status-retire-confirm">{t_i18n('Retire')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={previewing} onOpenChange={setPreviewing}>
        <DialogContent size="lg" style={{ ...layerInputVars } as React.CSSProperties}>
          <DialogTitle>{t_i18n('Preview the query a connector would run')}</DialogTitle>
          <DialogDescription>{t_i18n('The hunt connector translates the saved logic of the hunt without running it.')}</DialogDescription>
          <DialogBody>
            {previewing && (
              <Suspense fallback={<Spinner size="md" label={t_i18n('Loading')} />}>
                <HuntTranslationPreview huntId={hunt.id} huntType={hunt.hunt_type} scopePlatformIds={scopePlatformIds} autoStart />
              </Suspense>
            )}
          </DialogBody>
          <DialogFooter>
            <Button variant="secondary" onClick={() => setPreviewing(false)}>{t_i18n('Close')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default HuntStatusHeader;
