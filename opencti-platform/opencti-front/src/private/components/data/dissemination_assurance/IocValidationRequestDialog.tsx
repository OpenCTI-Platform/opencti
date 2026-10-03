import { ReactNode, Suspense, useEffect, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Alert, DialogActions, Stack, Typography } from '@mui/material';
import { Checkbox, Input, Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue, Textarea } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';
import {
  DEFAULT_TEST_KINDS,
  IOC_VALIDATION_MAX_INDICATORS,
  IOC_VALIDATION_MAX_PLATFORMS,
  type IocValidationTestKind,
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

interface IocValidationRequestDialogProps {
  open: boolean;
  onClose: () => void;
  indicatorIds: string[];
  platforms: ValidationPlatformOption[];
  defaultName: string;
  summary?: ReactNode;
}

const ConnectorSelection = ({ connectorId, onChange }: { connectorId: string | null; onChange: (id: string | null) => void }) => {
  const { t_i18n } = useFormatter();
  const { iocValidationConnectors } = useLazyLoadQuery<IocValidationRequestDialogConnectorsQuery>(
    iocValidationConnectorsQuery,
    {},
    { fetchPolicy: 'store-and-network' },
  );
  const connectors = iocValidationConnectors ?? [];
  const activeConnectors = connectors.filter((connector) => connector.active);
  useEffect(() => {
    if (!connectorId && activeConnectors.length > 0) onChange(activeConnectors[0].id);
  }, [connectorId, activeConnectors.length]);
  if (activeConnectors.length === 0) {
    return (
      <Alert severity="warning" variant="outlined" data-testid="ioc-validation-no-connector">
        {t_i18n('No OpenAEV IOC validation connector is active. Configure OpenCTI in OpenAEV to enable IOC validation.')}
      </Alert>
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

const IocValidationRequestDialog = ({ open, onClose, indicatorIds, platforms, defaultName, summary }: IocValidationRequestDialogProps) => {
  const { t_i18n } = useFormatter();
  const [selectedPlatforms, setSelectedPlatforms] = useState<string[]>(platforms.slice(0, IOC_VALIDATION_MAX_PLATFORMS).map((p) => p.id));
  const [testKinds, setTestKinds] = useState<IocValidationTestKind[]>(DEFAULT_TEST_KINDS);
  const [name, setName] = useState(defaultName);
  const [description, setDescription] = useState('');
  const [connectorId, setConnectorId] = useState<string | null>(null);
  const [commit, submitting] = useApiMutation<IocValidationRequestDialogMutation>(iocValidationRequestMutation);

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
    <Dialog open={open} onClose={onClose} title={t_i18n('Request validation in OpenAEV')} size="medium">
      <Stack gap={2} data-testid="ioc-validation-request-dialog">
        {summary && <Typography variant="body2">{summary}</Typography>}
        <Alert severity="info" variant="outlined">
          {t_i18n('OpenAEV runs benign tests built from each indicator and checks that the security platforms detected or prevented them. Every validation scenario must be approved in OpenAEV before it runs, and only the test kinds allowed there are executed.')}
        </Alert>
        {platforms.length > 1 && (
          <Stack gap={0.5}>
            <Typography variant="h4">{t_i18n('Security platforms')}</Typography>
            {platforms.map((platform) => (
              <Checkbox
                key={platform.id}
                label={platform.name}
                checked={selectedPlatforms.includes(platform.id)}
                onCheckedChange={() => togglePlatform(platform.id)}
              />
            ))}
            {tooManyPlatforms && (
              <Typography variant="caption" color="error">
                {t_i18n('A validation request covers at most 10 security platforms')}
              </Typography>
            )}
          </Stack>
        )}
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
            <Alert severity="warning" variant="outlined">
              {t_i18n('Network and HTTP tests reach the indicator values. OpenAEV only runs them when an administrator allowed them, through the egress proxy or the sinkhole it configured.')}
            </Alert>
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
          <Alert severity="error" variant="outlined">
            {t_i18n('A validation request covers at most 200 indicators')}
          </Alert>
        )}
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          {open && <ConnectorSelection connectorId={connectorId} onChange={setConnectorId} />}
        </Suspense>
      </Stack>
      <DialogActions>
        <Button variant="secondary" onClick={onClose} disabled={submitting}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={submit} disabled={!canSubmit} data-testid="ioc-validation-request-submit">
          {t_i18n('Request validation')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default IocValidationRequestDialog;
