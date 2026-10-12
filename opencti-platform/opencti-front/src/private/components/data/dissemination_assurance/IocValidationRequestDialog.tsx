import { ReactNode, Suspense, useEffect, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { DialogActions, Stack, Typography } from '@mui/material';
import { Alert, Checkbox, Input, Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue, Textarea } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useGranted, { MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import { MESSAGING$ } from '../../../../relay/environment';
import {
  DEFAULT_TEST_KINDS,
  IOC_VALIDATION_MAX_INDICATORS,
  IOC_VALIDATION_MAX_PLATFORMS,
  type IocValidationTestKind,
  selectedValidationConnectorId,
  TEST_KINDS,
  toggleTestKind,
} from './disseminationAssuranceUtils';
import type { IocValidationRequestDialogConnectorsQuery } from './__generated__/IocValidationRequestDialogConnectorsQuery.graphql';
import type { IocValidationRequestDialogMutation } from './__generated__/IocValidationRequestDialogMutation.graphql';

const iocValidationConnectorsQuery = graphql`
  query IocValidationRequestDialogConnectorsQuery {
    iocValidationConnectors {
      id
      name
      active
    }
  }
`;

const iocValidationRequestMutation = graphql`
  mutation IocValidationRequestDialogMutation(
    $platformIds: [StixRef!]!
    $indicatorIds: [StixRef!]!
    $testKinds: [IocValidationTestKind!]!
    $connectorId: ID
    $name: String
    $description: String
  ) {
    indicatorsRequestValidation(
      platformIds: $platformIds
      indicatorIds: $indicatorIds
      testKinds: $testKinds
      connectorId: $connectorId
      name: $name
      description: $description
    ) {
      id
      name
      status
      status_message
      results_summary {
        total
        skipped
      }
    }
  }
`;

export interface ValidationPlatformOption {
  id: string;
  name: string;
}

export interface ValidationIndicatorOption {
  id: string;
  name: string;
}

interface IocValidationRequestDialogProps {
  open: boolean;
  onClose: () => void;
  indicators: ValidationIndicatorOption[];
  platforms: ValidationPlatformOption[];
  defaultName: string;
  /** What the request covers, from the security platforms selected in the dialog (the ones submitted). */
  summary?: (selectedPlatformCount: number) => ReactNode;
}

const PREVIEW_SIZE = 5;

const ConnectorSelection = ({ connectorId, onChange }: { connectorId: string | null; onChange: (id: string | null) => void }) => {
  const { t_i18n } = useFormatter();
  const canManageConnectors = useGranted([MODULES_MODMANAGE]);
  const { iocValidationConnectors } = useLazyLoadQuery<IocValidationRequestDialogConnectorsQuery>(
    iocValidationConnectorsQuery,
    {},
    { fetchPolicy: 'store-and-network' },
  );
  const connectors = iocValidationConnectors ?? [];
  const activeConnectors = connectors.filter((connector) => connector.active);
  const activeConnectorIds = activeConnectors.map((connector) => connector.id);
  useEffect(() => {
    const selected = selectedValidationConnectorId(connectorId, activeConnectorIds);
    if (selected !== connectorId) onChange(selected);
  }, [connectorId, activeConnectorIds.join(',')]);
  if (activeConnectors.length === 0) {
    const settingsPath = connectors.length > 0 ? `/dashboard/integrations/connectors/${connectors[0].id}` : '/dashboard/integrations';
    return (
      <Alert
        severity="warning"
        data-testid="ioc-validation-no-connector"
        title={t_i18n('No OpenAEV IOC validation connector is active')}
        description={canManageConnectors
          ? t_i18n('Configure OpenCTI in OpenAEV, then check that its IOC validation connector is running.')
          : t_i18n('Ask an administrator to configure OpenCTI in OpenAEV and start its IOC validation connector.')}
        action={canManageConnectors ? (
          <Button variant="secondary" size="small" component={Link} to={settingsPath}>
            {t_i18n('Open connector settings')}
          </Button>
        ) : undefined}
      />
    );
  }
  if (activeConnectors.length === 1) return null;
  return (
    <Select value={connectorId ?? undefined} onValueChange={(value: string) => onChange(value)}>
      <SelectLabel>{t_i18n('OpenAEV IOC validation connector')}</SelectLabel>
      <SelectTrigger aria-label={t_i18n('OpenAEV IOC validation connector')}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent aria-label={t_i18n('OpenAEV IOC validation connector')}>
        {activeConnectors.map((connector) => (
          <SelectItem key={connector.id} value={connector.id}>{connector.name}</SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
};

/** What the request will test: the indicators (first ones, then all on demand). */
const TestedIndicators = ({ indicators }: { indicators: ValidationIndicatorOption[] }) => {
  const { t_i18n } = useFormatter();
  const [showAll, setShowAll] = useState(false);
  const visible = showAll ? indicators : indicators.slice(0, PREVIEW_SIZE);
  return (
    <Stack gap={0.5} data-testid="ioc-validation-tested-indicators">
      <Typography variant="h4">
        {t_i18n('{count, plural, one {# indicator to test} other {# indicators to test}}', { values: { count: indicators.length } })}
      </Typography>
      <Stack component="ul" gap={0.5} sx={{ listStyle: 'none', margin: 0, padding: 0, maxHeight: 220, overflowY: 'auto' }}>
        {visible.map((indicator) => (
          <Stack component="li" key={indicator.id} direction="row" alignItems="center" gap={1} sx={{ minWidth: 0 }}>
            <ItemIcon type="Indicator" size="small" />
            <Typography variant="body2" noWrap title={indicator.name}>{indicator.name}</Typography>
          </Stack>
        ))}
      </Stack>
      {indicators.length > PREVIEW_SIZE && (
        <div>
          <Button variant="tertiary" size="small" onClick={() => setShowAll((current) => !current)} aria-expanded={showAll}>
            {showAll
              ? t_i18n('Show fewer')
              : t_i18n('Show all {count} indicators', { values: { count: indicators.length } })}
          </Button>
        </div>
      )}
    </Stack>
  );
};

const IocValidationRequestDialog = ({ open, onClose, indicators, platforms, defaultName, summary }: IocValidationRequestDialogProps) => {
  const { t_i18n } = useFormatter();
  const [selectedPlatforms, setSelectedPlatforms] = useState<string[]>(platforms.slice(0, IOC_VALIDATION_MAX_PLATFORMS).map((p) => p.id));
  const [testKinds, setTestKinds] = useState<IocValidationTestKind[]>(DEFAULT_TEST_KINDS);
  const [name, setName] = useState(defaultName);
  const [description, setDescription] = useState('');
  const [connectorId, setConnectorId] = useState<string | null>(null);
  const [commit, submitting] = useApiMutation<IocValidationRequestDialogMutation>(iocValidationRequestMutation);
  const indicatorIds = indicators.map((indicator) => indicator.id);

  useEffect(() => {
    if (open) {
      setSelectedPlatforms(platforms.slice(0, IOC_VALIDATION_MAX_PLATFORMS).map((p) => p.id));
      setTestKinds(DEFAULT_TEST_KINDS);
      setName(defaultName);
      setDescription('');
    }
  }, [open, platforms.map((p) => p.id).join(','), defaultName]);

  const togglePlatform = (platformId: string) => {
    setSelectedPlatforms((current) => (current.includes(platformId) ? current.filter((id) => id !== platformId) : [...current, platformId]));
  };

  const tooManyPlatforms = selectedPlatforms.length > IOC_VALIDATION_MAX_PLATFORMS;
  const tooManyIndicators = indicatorIds.length > IOC_VALIDATION_MAX_INDICATORS;
  const canSubmit = !submitting && !!connectorId && indicatorIds.length > 0 && selectedPlatforms.length > 0
    && testKinds.length > 0 && !tooManyPlatforms && !tooManyIndicators && name.trim().length > 0;

  const submit = () => {
    commit({
      variables: {
        platformIds: selectedPlatforms,
        indicatorIds,
        testKinds,
        connectorId,
        name: name.trim(),
        description: description.trim() || null,
      },
      // Payload errors reach onCompleted: the inputs are kept until a request is actually created.
      onCompleted: (response, errors) => {
        const request = response.indicatorsRequestValidation;
        if ((errors && errors.length > 0) || !request) {
          MESSAGING$.notifyError(errors?.[0]?.message ?? t_i18n('The validation request could not be created'));
          return;
        }
        if (request.status === 'failed') {
          MESSAGING$.notifyError(request.status_message ?? t_i18n('The validation request could not be sent to OpenAEV'));
        } else if (request.status === 'pending') {
          MESSAGING$.notifySuccess(t_i18n('Validation request saved, it is sent once an OpenAEV IOC validation connector is active'));
        } else {
          MESSAGING$.notifySuccess(t_i18n('Validation request sent to OpenAEV, it runs once approved there'));
        }
        onClose();
      },
    });
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t_i18n('Request validation in OpenAEV')}
      size="medium"
      contentProps={{ style: { display: 'flex', flexDirection: 'column', overflowY: 'hidden' } }}
    >
      {/* The body scrolls on its own so the footer stays in view on short screens; the 4px padding given back and
          taken out again keeps the focus ring the library paints outside the fields. */}
      <Stack
        gap={2}
        data-testid="ioc-validation-request-dialog"
        sx={{ flex: '1 1 auto', minHeight: 0, overflowY: 'auto', position: 'relative', p: 0.5, m: -0.5 }}
      >
        {summary && <Typography variant="body2" data-testid="validation-request-summary">{summary(selectedPlatforms.length)}</Typography>}
        <Alert
          severity="info"
          title={t_i18n('Every validation scenario is approved in OpenAEV before it runs')}
          description={t_i18n('Benign tests of each indicator check that the platforms detected or prevented them.')}
        />
        {indicators.length > 0 && <TestedIndicators indicators={indicators} />}
        <Stack gap={0.5}>
          <Typography variant="h4">{t_i18n('Security platforms')}</Typography>
          {platforms.length > 1 ? platforms.map((platform) => (
            <Checkbox
              key={platform.id}
              label={platform.name}
              checked={selectedPlatforms.includes(platform.id)}
              onCheckedChange={() => togglePlatform(platform.id)}
            />
          )) : platforms.map((platform) => (
            <Stack key={platform.id} direction="row" alignItems="center" gap={1}>
              <ItemIcon type="SecurityPlatform" size="small" />
              <Typography variant="body2">{platform.name}</Typography>
            </Stack>
          ))}
          {tooManyPlatforms && (
            <Typography variant="caption" color="error">
              {t_i18n('A validation request covers at most 10 security platforms')}
            </Typography>
          )}
        </Stack>
        <Stack gap={0.5}>
          <Typography variant="h4">{t_i18n('Test kinds')}</Typography>
          {TEST_KINDS.map((definition) => (
            <Checkbox
              key={definition.kind}
              label={t_i18n(definition.label)}
              description={t_i18n(definition.description)}
              checked={testKinds.includes(definition.kind)}
              onCheckedChange={() => setTestKinds((current) => toggleTestKind(current, definition.kind))}
              data-testid={`ioc-validation-test-kind-${definition.kind}`}
            />
          ))}
          {testKinds.some((kind) => TEST_KINDS.find((definition) => definition.kind === kind)?.contactsInfrastructure) && (
            <Alert
              severity="warning"
              title={t_i18n('Network and HTTP tests reach the indicator values')}
              description={t_i18n('OpenAEV only runs them when an administrator allowed them, through the egress proxy or the sinkhole it configured.')}
            />
          )}
        </Stack>
        <Input
          label={t_i18n('Name')}
          value={name}
          required
          error={name.trim().length === 0 ? t_i18n('This field is required') : undefined}
          onChange={(event) => setName(event.target.value)}
        />
        <Textarea
          label={t_i18n('Description')}
          value={description}
          rows={2}
          onChange={(event) => setDescription(event.target.value)}
        />
        {tooManyIndicators && (
          <Alert severity="error" title={t_i18n('A validation request covers at most 200 indicators')} />
        )}
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          {open && <ConnectorSelection connectorId={connectorId} onChange={setConnectorId} />}
        </Suspense>
      </Stack>
      <DialogActions sx={{ flexShrink: 0 }}>
        <Button variant="secondary" onClick={onClose} disabled={submitting}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={submit} disabled={!canSubmit} data-testid="ioc-validation-request-submit">
          {t_i18n('Validate {count, plural, one {# indicator} other {# indicators}}', { values: { count: indicatorIds.length } })}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default IocValidationRequestDialog;
