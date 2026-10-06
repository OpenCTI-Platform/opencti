import React, { Suspense, useEffect, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link, useNavigate } from 'react-router';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { PlayArrowOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import {
  Alert,
  Checkbox,
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
  Spinner,
  Text,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { MESSAGING$ } from '../../../../relay/environment';
import { mutationErrorMessage, payloadErrorsMessage, useDialogMutation } from '../hunt-mutation-utils';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { canStartHuntRun, HUNT_MAX_TIME_WINDOW_HOURS } from '../hunt-utils';

// The hunt connectors page, as its status header links it
const HUNT_CONNECTORS_PATH = '/dashboard/data/ingestion/connectors';
import { PATH_HUNT } from '../../common/routes/paths';
import { insertStartedHuntRuns } from './hunt-run-store';
import { HuntRunStartConnectorsQuery } from './__generated__/HuntRunStartConnectorsQuery.graphql';
import { HuntRunStartMutation } from './__generated__/HuntRunStartMutation.graphql';

const huntRunStartConnectorsQuery = graphql`
  query HuntRunStartConnectorsQuery {
    huntConnectors(onlyAlive: true) {
      id
      name
      platform
      supports_indicators
      securityPlatform {
        id
        name
      }
    }
  }
`;

const huntRunStartMutation = graphql`
  mutation HuntRunStartMutation($id: ID!, $input: HuntRunStartInput) {
    huntRunStart(id: $id, input: $input) {
      id
      ...HuntRuns_RunFragment
    }
  }
`;

interface RunStartValues {
  security_platform_ids: string[];
  time_window_hours: number | string;
}

interface PlatformOption {
  id: string;
  name: string;
}

interface PlatformChoicesProps {
  selected: string[];
  onChange: (ids: string[]) => void;
  scopePlatformIds: string[];
  huntType: string;
  onCount: (count: number) => void;
}

const PlatformChoices = ({ selected, onChange, scopePlatformIds, huntType, onCount }: PlatformChoicesProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { huntConnectors } = useLazyLoadQuery<HuntRunStartConnectorsQuery>(huntRunStartConnectorsQuery, {}, { fetchPolicy: 'store-and-network' });
  const platforms = new Map<string, PlatformOption>();
  huntConnectors.forEach((connector) => {
    if (huntType === 'indicators' && !connector.supports_indicators) {
      return;
    }
    if (connector.securityPlatform && (scopePlatformIds.length === 0 || scopePlatformIds.includes(connector.securityPlatform.id))) {
      platforms.set(connector.securityPlatform.id, { id: connector.securityPlatform.id, name: connector.securityPlatform.name });
    }
  });
  const options = Array.from(platforms.values()).sort((a, b) => a.name.localeCompare(b.name));
  useEffect(() => onCount(options.length), [options.length]);
  if (options.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1), alignItems: 'flex-start' }} data-testid="hunt-run-start-no-connector">
        <Text variant="content-compact">
          {huntType === 'indicators'
            ? t_i18n('No hunt connector of its scope supports indicator lookups: deploy one that does, such as the Splunk hunt connector')
            : t_i18n('No hunt connector can run it on the platforms of its scope: deploy a hunt connector or widen the scope')}
        </Text>
        <Button variant="secondary" size="small" component={Link} to={HUNT_CONNECTORS_PATH}>{t_i18n('Open the hunt connectors')}</Button>
      </div>
    );
  }
  const toggle = (id: string, checked: boolean) => onChange(checked ? [...selected, id] : selected.filter((value) => value !== id));
  return (
    <fieldset
      // The padding keeps the hover and focus rings of the checkboxes inside the scrolling body of the dialog
      style={{ border: 'none', margin: 0, padding: theme.spacing(1), display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}
      data-testid="hunt-run-start-platforms"
    >
      <legend style={{ marginBottom: theme.spacing(1) }}>
        <Text variant="content-compact">{t_i18n('Security platforms (none selected means every platform of the scope)')}</Text>
      </legend>
      {options.map((option) => (
        <Checkbox
          key={option.id}
          label={option.name}
          checked={selected.includes(option.id)}
          onCheckedChange={(checked) => toggle(option.id, checked === true)}
        />
      ))}
    </fieldset>
  );
};

interface HuntRunStartProps {
  hunt: {
    id: string;
    hunt_status: string;
    hunt_type: string;
    time_window_hours: number;
    scopePlatforms?: ReadonlyArray<{ id: string; name: string }> | null;
  };
  paginationOptions?: Record<string, unknown>;
  /** Renders a compact button, for the tab bar of the hunt */
  compact?: boolean;
}

const HuntRunStart = ({ hunt, paginationOptions, compact = false }: HuntRunStartProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const draftContext = useDraftContext();
  const [open, setOpen] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  // null while unknown, and for infrastructure hunts, which run on the internet hunt connectors
  const [runnablePlatforms, setRunnablePlatforms] = useState<number | null>(null);
  const [commit] = useDialogMutation<HuntRunStartMutation>(huntRunStartMutation);
  const openDialog = (next: boolean) => {
    setRunError(null);
    setRunnablePlatforms(null);
    setOpen(next);
  };
  const canRun = canStartHuntRun(hunt.hunt_status, !!draftContext);
  const scopePlatformIds = (hunt.scopePlatforms ?? []).map((platform) => platform.id);
  const validation = Yup.object().shape({
    time_window_hours: Yup.number()
      .typeError(t_i18n('The value must be a number'))
      .integer(t_i18n('The value must be an integer'))
      .min(1, t_i18n('The value must be greater than or equal to {value}', { values: { value: 1 } }))
      .max(HUNT_MAX_TIME_WINDOW_HOURS, t_i18n('The value must be less than or equal to {value}', { values: { value: HUNT_MAX_TIME_WINDOW_HOURS } }))
      .required(t_i18n('This field is required')),
  });
  let disabledReason: string | null = null;
  if (draftContext) {
    disabledReason = t_i18n('A hunt runs once it is validated from its draft');
  } else if (!canRun) {
    disabledReason = t_i18n('Only active or paused hunts can run: activate the hunt from its status');
  }

  const onSubmit = (values: RunStartValues, { setSubmitting }: { setSubmitting: (submitting: boolean) => void }) => {
    setRunError(null);
    commit({
      variables: {
        id: hunt.id,
        input: {
          security_platform_ids: values.security_platform_ids.length > 0 ? values.security_platform_ids : null,
          time_window_hours: Number(values.time_window_hours),
        },
      },
      updater: (store) => {
        if (paginationOptions) {
          insertStartedHuntRuns(store, store.getPluralRootField('huntRunStart') ?? [], paginationOptions);
        }
      },
      onCompleted: (data, errors) => {
        setSubmitting(false);
        const errorMessage = payloadErrorsMessage(errors);
        if (errorMessage || !data.huntRunStart) {
          setRunError(errorMessage ?? t_i18n('The hunt could not be started'));
          return;
        }
        setOpen(false);
        const count = data.huntRunStart.length;
        MESSAGING$.notifySuccess(t_i18n('{count, plural, one {# run started} other {# runs started}}', { values: { count } }));
        if (count === 1) {
          navigate(`${PATH_HUNT(hunt.id)}/runs/${data.huntRunStart[0].id}`);
        } else {
          navigate(`${PATH_HUNT(hunt.id)}/runs`);
        }
      },
      onError: (error) => {
        setSubmitting(false);
        setRunError(mutationErrorMessage(error, t_i18n('The hunt could not be started')));
      },
    });
  };

  const runButton = (
    <Button
      size={compact ? 'default' : 'small'}
      variant={compact ? 'secondary' : 'primary'}
      startIcon={<PlayArrowOutlined fontSize="small" />}
      disabled={!canRun}
      onClick={() => openDialog(true)}
      data-testid="hunt-run-start"
    >
      {t_i18n('Run now')}
    </Button>
  );

  return (
    <>
      {disabledReason ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span>{runButton}</span>
          </TooltipTrigger>
          <TooltipContent>{disabledReason}</TooltipContent>
        </Tooltip>
      ) : runButton}
      <Dialog open={open} onOpenChange={openDialog}>
        <DialogContent size="md" data-testid="hunt-run-start-dialog">
          <DialogTitle>{t_i18n('Run the hunt now')}</DialogTitle>
          <DialogDescription>
            {t_i18n('The hunt is dispatched to the hunt connectors of its scope; each platform gets its own run.')}
          </DialogDescription>
          <Formik<RunStartValues>
            initialValues={{ security_platform_ids: [], time_window_hours: hunt.time_window_hours }}
            validationSchema={validation}
            onSubmit={onSubmit}
          >
            {({ values, setFieldValue, submitForm, isSubmitting }) => (
              <Form style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(3), flex: 1, minHeight: 0 }}>
                <DialogBody>
                  {hunt.hunt_type === 'infrastructure' ? (
                    <Text variant="content-compact">{t_i18n('Infrastructure hunts run on the internet hunt connectors')}</Text>
                  ) : (
                    <Suspense fallback={<Spinner size="md" label={t_i18n('Loading')} />}>
                      <PlatformChoices
                        selected={values.security_platform_ids}
                        onChange={(ids) => setFieldValue('security_platform_ids', ids)}
                        scopePlatformIds={scopePlatformIds}
                        huntType={hunt.hunt_type}
                        onCount={setRunnablePlatforms}
                      />
                    </Suspense>
                  )}
                  <div style={{ marginTop: theme.spacing(2) }}>
                    <Field
                      component={TextField}
                      name="time_window_hours"
                      type="number"
                      label={t_i18n('Time window (hours)')}
                      fullWidth
                      required
                    />
                  </div>
                  {runError && (
                    <div style={{ marginTop: theme.spacing(2) }} role="alert">
                      <Alert severity="error" title={t_i18n('The hunt could not be started')} description={runError} data-testid="hunt-run-start-error" />
                    </div>
                  )}
                </DialogBody>
                <DialogFooter>
                  <Button variant="secondary" onClick={() => openDialog(false)} disabled={isSubmitting}>
                    {t_i18n('Cancel')}
                  </Button>
                  <Button onClick={submitForm} disabled={isSubmitting || runnablePlatforms === 0} data-testid="hunt-run-start-submit">
                    {t_i18n('Run')}
                  </Button>
                </DialogFooter>
              </Form>
            )}
          </Formik>
        </DialogContent>
      </Dialog>
    </>
  );
};

export default HuntRunStart;
