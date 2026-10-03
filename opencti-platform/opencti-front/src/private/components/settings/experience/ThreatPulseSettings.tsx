import React, { Suspense, useState } from 'react';
import { graphql, useFragment, useLazyLoadQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import DialogActions from '@mui/material/DialogActions';
import { useTheme } from '@mui/styles';
import { BarChartOutlined, LockOutlined, NotificationsActiveOutlined, PublicOutlined, SensorsOutlined, TimelineOutlined } from '@mui/icons-material';
import {
  Checkbox,
  Chip,
  Combobox,
  ComboboxChips,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  Text,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Tag from '@common/tag/Tag';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from '../../../../utils/hooks/useGranted';
import { MESSAGING$ } from '../../../../relay/environment';
import ExperienceCard, { ExperienceHeadline } from './ExperienceCard';
import ExperienceDetailRow from './ExperienceDetailRow';
import ExperienceFeatureTile from './ExperienceFeatureTile';
import { PULSE_CONTRIBUTION_STATUS_LABELS, PULSE_MODE_LABELS, PULSE_REGION_LABELS, PULSE_SECTOR_LABELS } from '../../common/threat_pulse/threatPulseUtils';
import { ThreatPulseSettingsQuery } from './__generated__/ThreatPulseSettingsQuery.graphql';
import { ThreatPulseSettings_settings$data, ThreatPulseSettings_settings$key } from './__generated__/ThreatPulseSettings_settings.graphql';
import { ThreatPulseSettingsConfigureMutation } from './__generated__/ThreatPulseSettingsConfigureMutation.graphql';
import { ThreatPulseSettingsPurgeMutation } from './__generated__/ThreatPulseSettingsPurgeMutation.graphql';

type ConfigureInput = ThreatPulseSettingsConfigureMutation['variables']['input'];
type PulseMode = ConfigureInput['mode'];
type PulseSectorBucket = NonNullable<ConfigureInput['sector_bucket']>;
type PulseRegionBucket = NonNullable<ConfigureInput['region_bucket']>;

const threatPulseSettingsFragment = graphql`
  fragment ThreatPulseSettings_settings on PulseSettings {
    id
    mode
    access
    enabled
    readable
    hub_registered
    consent_version
    consent_accepted_version
    consent_date
    consent_user_name
    scopes
    available_scopes
    excluded_markings {
      id
      definition
      x_opencti_color
    }
    forced_excluded_markings {
      id
      definition
      x_opencti_color
    }
    sector_bucket
    region_bucket
    suggested_sector_bucket
    suggested_region_bucket
    contribution {
      last_push_at
      last_refresh_at
      last_error
      total_records
      days {
        day
        records
        objects
      }
      by_type {
        entity_type
        records
      }
    }
    preview {
      last_refresh_at
      digest_day
      digest_items
      matched_entities
    }
    network {
      reachable
      k_threshold
      retention_months
      contributors_bucket
      read_access
      last_contribution_day
      contribution_status
      read_access_until
      contribution_grace_days
    }
  }
`;

export const threatPulseSettingsQuery = graphql`
  query ThreatPulseSettingsQuery($withMarkings: Boolean!) {
    pulseSettings {
      ...ThreatPulseSettings_settings
    }
    markingDefinitions(first: 500, orderBy: definition_type) @include(if: $withMarkings) {
      edges {
        node {
          id
          definition
          x_opencti_color
        }
      }
    }
  }
`;

const threatPulseSettingsConfigureMutation = graphql`
  mutation ThreatPulseSettingsConfigureMutation($input: PulseConfigurationInput!) {
    pulseConfigure(input: $input) {
      ...ThreatPulseSettings_settings
    }
  }
`;

const threatPulseSettingsPurgeMutation = graphql`
  mutation ThreatPulseSettingsPurgeMutation {
    pulsePurge {
      success
      deleted_records
    }
  }
`;

const SECTOR_VALUES = Object.keys(PULSE_SECTOR_LABELS) as PulseSectorBucket[];
const REGION_VALUES = Object.keys(PULSE_REGION_LABELS) as PulseRegionBucket[];
const MODES: PulseMode[] = ['preview', 'contribute_and_read', 'off'];
export const THREAT_PULSE_DOCUMENTATION_URL = 'https://docs.opencti.io/latest/usage/threat-pulse/';

interface MarkingOption {
  id: string;
  definition: string | null | undefined;
  x_opencti_color: string | null | undefined;
}

// The markings an administrator may exclude: the platform markings (fetched for administrators only) and the ones
// already excluded, so that every user sees the current exclusions.
const toMarkingOptions = (markings: MarkingOption[], settings: ThreatPulseSettings_settings$data): MarkingOption[] => {
  const forcedIds = settings.forced_excluded_markings.map((marking) => marking.id);
  const options = markings.filter((marking) => !forcedIds.includes(marking.id));
  const missing = settings.excluded_markings.filter((excluded) => !options.some((marking) => marking.id === excluded.id));
  return [...options, ...missing];
};

interface PrivacyFieldsProps {
  availableScopes: readonly string[];
  scopes: string[];
  onScopesChange: (scopes: string[]) => void;
  forcedMarkings: readonly MarkingOption[];
  markingOptions: MarkingOption[];
  excludedIds: string[];
  onExcludedChange: (ids: string[]) => void;
  disabled: boolean;
}

const ThreatPulsePrivacyFields = ({
  availableScopes,
  scopes,
  onScopesChange,
  forcedMarkings,
  markingOptions,
  excludedIds,
  onExcludedChange,
  disabled,
}: PrivacyFieldsProps) => {
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const theme = useTheme<Theme>();
  return (
    <>
      <Box sx={{ paddingY: 1.25 }}>
        <Combobox<string>
          multiple
          options={[...availableScopes]}
          value={scopes}
          getOptionLabel={(scope) => translateEntityType(scope)}
          disabled={disabled}
          clearable={false}
          onValueChange={(value) => {
            const next = value as string[];
            if (next.length > 0) onScopesChange(next);
          }}
        >
          <ComboboxLabel>{t_i18n('Contributed entity types')}</ComboboxLabel>
          <ComboboxField>
            <ComboboxChips aria-label={t_i18n('Contributed entity types')} />
            <ComboboxInput name="pulse_scopes" />
            <ComboboxControls><ComboboxTrigger /></ComboboxControls>
          </ComboboxField>
          <ComboboxContent listAriaLabel={t_i18n('Contributed entity types')} />
        </Combobox>
      </Box>
      <Box sx={{ paddingY: 1.25, display: 'flex', flexDirection: 'column', gap: 1 }}>
        <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{t_i18n('Always excluded')}</Text>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          {forcedMarkings.map((marking) => (
            <Box key={marking.id} sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.5 }}>
              <LockOutlined fontSize="small" color="disabled" />
              <Chip label={marking.definition ?? ''} color={marking.x_opencti_color ?? undefined} />
            </Box>
          ))}
        </Box>
        <Combobox<MarkingOption>
          multiple
          options={markingOptions}
          value={markingOptions.filter((marking) => excludedIds.includes(marking.id))}
          getOptionLabel={(marking) => marking.definition ?? ''}
          isOptionEqualToValue={(a, b) => a.id === b.id}
          getChipColor={(marking) => marking.x_opencti_color ?? undefined}
          disabled={disabled}
          onValueChange={(value) => onExcludedChange((value as MarkingOption[]).map((marking) => marking.id))}
        >
          <ComboboxLabel>{t_i18n('Additional excluded markings')}</ComboboxLabel>
          <ComboboxField>
            <ComboboxChips aria-label={t_i18n('Additional excluded markings')} />
            <ComboboxInput name="pulse_excluded_markings" />
            <ComboboxControls><ComboboxTrigger /></ComboboxControls>
          </ComboboxField>
          <ComboboxContent listAriaLabel={t_i18n('Additional excluded markings')} />
        </Combobox>
      </Box>
    </>
  );
};

interface ConsentInput {
  sector: PulseSectorBucket;
  region: PulseRegionBucket;
  scopes: string[];
  excludedIds: string[];
}

interface ConsentDialogProps {
  open: boolean;
  settings: ThreatPulseSettings_settings$data;
  markingOptions: MarkingOption[];
  onClose: () => void;
  onAccept: (input: ConsentInput) => void;
}

const ThreatPulseConsentDialog = ({ open, settings, markingOptions, onClose, onAccept }: ConsentDialogProps) => {
  const { t_i18n } = useFormatter();
  const [accepted, setAccepted] = useState(false);
  const [sector, setSector] = useState<PulseSectorBucket>(settings.sector_bucket ?? settings.suggested_sector_bucket);
  const [region, setRegion] = useState<PulseRegionBucket>(settings.region_bucket ?? settings.suggested_region_bucket);
  const [scopes, setScopes] = useState<string[]>([...settings.scopes]);
  const [excludedIds, setExcludedIds] = useState<string[]>(settings.excluded_markings.map((marking) => marking.id));
  return (
    <Dialog open={open} onClose={onClose} title={t_i18n('Contribute to Threat Pulse')} size="medium">
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }} data-testid="threat-pulse-consent-dialog">
        <Text variant="content-compact">
          {t_i18n('By contributing, this platform sends to XTM Hub, every hour, keyed hashes of the indicators, attack patterns, vulnerabilities, intrusion sets, malware and tools it observes, with activity counts. Raw values, names, descriptions, files and the identity of your organization never leave the platform.')}
        </Text>
        <Text variant="content-compact">
          {t_i18n('Hashes are derived with a salt that XTM Hub rotates every day. Objects marked TLP:RED, TLP:AMBER+STRICT or PAP:RED, objects with restricted access and the markings you exclude never contribute.')}
        </Text>
        <Text variant="content-compact">
          {t_i18n('XTM Hub publishes a signal only when enough distinct platforms observed the same object (k-anonymity). Your sector and region are shared as coarse buckets only.')}
        </Text>
        <Text variant="content-compact">
          {t_i18n('Contributing unlocks the full experience: platforms range, network first seen, 12-week trend, sector trend, trending alerts, benchmarks and briefings. You can stop contributing at any time and purge every contribution of this platform; the preview stays available and sends nothing.')}
        </Text>
        <a href={THREAT_PULSE_DOCUMENTATION_URL} target="_blank" rel="noopener noreferrer">
          <Text variant="content-compact">{t_i18n('Read what is shared in each mode')}</Text>
        </a>
        <Select value={sector} onValueChange={(value) => setSector(value as PulseSectorBucket)}>
          <SelectLabel>{t_i18n('Sector bucket')}</SelectLabel>
          <SelectTrigger aria-label={t_i18n('Sector bucket')}>
            <SelectValue>{t_i18n(PULSE_SECTOR_LABELS[sector])}</SelectValue>
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Sector bucket')}>
            {SECTOR_VALUES.map((value) => <SelectItem key={value} value={value}>{t_i18n(PULSE_SECTOR_LABELS[value])}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={region} onValueChange={(value) => setRegion(value as PulseRegionBucket)}>
          <SelectLabel>{t_i18n('Region bucket')}</SelectLabel>
          <SelectTrigger aria-label={t_i18n('Region bucket')}>
            <SelectValue>{t_i18n(PULSE_REGION_LABELS[region])}</SelectValue>
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Region bucket')}>
            {REGION_VALUES.map((value) => <SelectItem key={value} value={value}>{t_i18n(PULSE_REGION_LABELS[value])}</SelectItem>)}
          </SelectContent>
        </Select>
        <Box data-testid="threat-pulse-consent-privacy">
          <Text variant="content-compact">{t_i18n('Choose what this platform contributes: these choices apply before anything is sent.')}</Text>
          <ThreatPulsePrivacyFields
            availableScopes={settings.available_scopes}
            scopes={scopes}
            onScopesChange={setScopes}
            forcedMarkings={settings.forced_excluded_markings}
            markingOptions={markingOptions}
            excludedIds={excludedIds}
            onExcludedChange={setExcludedIds}
            disabled={false}
          />
        </Box>
        <Checkbox
          checked={accepted}
          onCheckedChange={(checked) => setAccepted(checked === true)}
          label={t_i18n('I have read and accept the Threat Pulse terms on behalf of my organization')}
          data-testid="threat-pulse-consent-checkbox"
        />
      </Box>
      <DialogActions>
        <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
        <Button
          disabled={!accepted || scopes.length === 0}
          onClick={() => onAccept({ sector, region, scopes, excludedIds })}
          data-testid="threat-pulse-consent-accept"
        >
          {t_i18n('Contribute')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

interface ThreatPulseSettingsComponentProps {
  settingsKey: ThreatPulseSettings_settings$key;
  markings: MarkingOption[];
}

const ThreatPulseSettingsComponent = ({ settingsKey, markings }: ThreatPulseSettingsComponentProps) => {
  const { t_i18n, fldt, n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const theme = useTheme<Theme>();
  const secondary = { color: theme.palette.text.secondary };
  const settings = useFragment(threatPulseSettingsFragment, settingsKey);
  const isGranted = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const [openConsent, setOpenConsent] = useState(false);
  const [openPurge, setOpenPurge] = useState(false);
  const [commitConfigure, configuring] = useApiMutation<ThreatPulseSettingsConfigureMutation>(threatPulseSettingsConfigureMutation);
  const [commitPurge, purging] = useApiMutation<ThreatPulseSettingsPurgeMutation>(threatPulseSettingsPurgeMutation);
  const accent = theme.palette.xtmhub?.main ?? theme.palette.designSystem.primary.main;
  const markingOptions = toMarkingOptions(markings, settings);

  const configure = (input: Partial<ConfigureInput>) => {
    commitConfigure({ variables: { input: { mode: settings.mode, ...input } } });
  };
  const purge = () => {
    commitPurge({
      variables: {},
      onCompleted: (response, errors) => {
        if ((errors && errors.length > 0) || !response?.pulsePurge?.success) {
          MESSAGING$.notifyError(t_i18n('XTM Hub did not purge the contributions of this platform. Try again later.'));
          return;
        }
        setOpenPurge(false);
        MESSAGING$.notifySuccess(`${n(response.pulsePurge.deleted_records)} ${t_i18n('contributions purged from XTM Hub')}`);
      },
    });
  };

  const lapsed = settings.mode === 'contribute_and_read' && settings.access === 'preview';
  let statusChip = <Tag label={t_i18n('Off')} labelTextTransform="none" disableTooltip />;
  if (settings.access === 'not_connected') {
    statusChip = <Tag label={t_i18n('Not connected')} labelTextTransform="none" disableTooltip />;
  } else if (settings.access === 'full') {
    statusChip = <Tag label={t_i18n('Contributing - full experience')} color={theme.palette.success.main} labelTextTransform="none" disableTooltip />;
  } else if (lapsed) {
    statusChip = <Tag label={t_i18n('Contribution lapsed - preview')} labelTextTransform="none" disableTooltip />;
  } else if (settings.access === 'preview') {
    statusChip = <Tag label={t_i18n('Preview')} color={accent} labelTextTransform="none" disableTooltip />;
  }

  const footer = isGranted ? (
    <>
      {settings.enabled && (
        <Button variant="secondary" color="error" onClick={() => setOpenPurge(true)} disabled={purging} data-testid="threat-pulse-purge-button">
          {t_i18n('Purge my contributions')}
        </Button>
      )}
      {settings.enabled && (
        <Button variant="secondary" onClick={() => configure({ mode: 'preview' })} disabled={configuring} data-testid="threat-pulse-stop-button">
          {t_i18n('Stop contributing')}
        </Button>
      )}
      {settings.mode === 'preview' && (
        <Button variant="secondary" onClick={() => configure({ mode: 'off' })} disabled={configuring} data-testid="threat-pulse-disable-button">
          {t_i18n('Turn Threat Pulse off')}
        </Button>
      )}
      {settings.mode === 'off' && (
        <Button variant="secondary" onClick={() => configure({ mode: 'preview' })} disabled={!settings.hub_registered || configuring} data-testid="threat-pulse-preview-button">
          {t_i18n('Turn the preview on')}
        </Button>
      )}
      {!settings.enabled && (
        <Button onClick={() => setOpenConsent(true)} disabled={!settings.hub_registered || configuring} data-testid="threat-pulse-enable-button">
          {t_i18n('Contribute and unlock the full experience')}
        </Button>
      )}
    </>
  ) : undefined;

  const previewStatus = settings.mode === 'preview' && settings.hub_registered && (
    <div data-testid="threat-pulse-preview-status">
      <ExperienceDetailRow label={t_i18n('Sent by the preview')}>
        <Text variant="content-compact">{t_i18n('Nothing: the digest is downloaded and matched on this platform')}</Text>
      </ExperienceDetailRow>
      <ExperienceDetailRow label={t_i18n('Objects found in the community digest')}>
        <Text variant="content-compact" data-testid="threat-pulse-preview-matched">{n(settings.preview.matched_entities)}</Text>
      </ExperienceDetailRow>
      <ExperienceDetailRow label={t_i18n('Last preview refresh')} divider={false}>
        <Text variant="content-compact">
          {settings.preview.last_refresh_at ? `${fldt(settings.preview.last_refresh_at)} - ${n(settings.preview.digest_items)} ${t_i18n('objects in the digest')}` : '-'}
        </Text>
      </ExperienceDetailRow>
    </div>
  );

  const pitch = (
    <>
      <ExperienceHeadline>{t_i18n('The open network early warning system')}</ExperienceHeadline>
      <Text variant="content-compact" style={secondary}>
        {t_i18n('The preview shows how widespread your objects are across the community and whether they rise, without sending anything. Contribute keyed hashes and counts, never values, to unlock network first seen, platforms ranges, sector trends, alerts and benchmarks.')}
      </Text>
      {previewStatus}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: theme.spacing(1.5) }}>
        <ExperienceFeatureTile accent={accent} icon={<PublicOutlined />} label={t_i18n('Community prevalence')} />
        <ExperienceFeatureTile accent={accent} icon={<TimelineOutlined />} label={t_i18n('Network first seen and trends')} />
        <ExperienceFeatureTile accent={accent} icon={<NotificationsActiveOutlined />} label={t_i18n('Trending in your sector alerts')} />
        <ExperienceFeatureTile accent={accent} icon={<BarChartOutlined />} label={t_i18n('Sector benchmarks')} />
      </div>
      {!settings.hub_registered && (
        <Alert severity="info" variant="outlined">{t_i18n('Register the platform on XTM Hub to use Threat Pulse.')}</Alert>
      )}
    </>
  );

  const configuration = (
    <div data-testid="threat-pulse-configuration">
      {lapsed && (
        <Alert severity="warning" variant="outlined" data-testid="threat-pulse-lapsed" style={{ marginBottom: theme.spacing(1) }}>
          {t_i18n('XTM Hub received no contribution from this platform within the grace period: the preview is shown until the next contribution is accepted.')}
        </Alert>
      )}
      <ExperienceDetailRow label={t_i18n('Mode')}>
        <Select
          value={settings.mode}
          disabled={!isGranted || configuring}
          onValueChange={(value) => {
            if (value === 'contribute_and_read' && !settings.enabled) {
              setOpenConsent(true);
            } else {
              configure({ mode: value as PulseMode });
            }
          }}
        >
          <SelectTrigger aria-label={t_i18n('Mode')} style={{ width: 240 }}>
            <SelectValue>{t_i18n(PULSE_MODE_LABELS[settings.mode])}</SelectValue>
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Mode')}>
            {MODES.map((value) => <SelectItem key={value} value={value}>{t_i18n(PULSE_MODE_LABELS[value])}</SelectItem>)}
          </SelectContent>
        </Select>
      </ExperienceDetailRow>
      {settings.network.contribution_status && (
        <ExperienceDetailRow label={t_i18n('Contribution status')}>
          <Text variant="content-compact" data-testid="threat-pulse-contribution-status">
            {`${t_i18n(PULSE_CONTRIBUTION_STATUS_LABELS[settings.network.contribution_status] ?? settings.network.contribution_status)}${settings.network.read_access_until ? ` - ${t_i18n('full experience until')} ${settings.network.read_access_until}` : ''}`}
          </Text>
        </ExperienceDetailRow>
      )}
      <ExperienceDetailRow label={t_i18n('Sector bucket')}>
        <Select
          value={settings.sector_bucket ?? settings.suggested_sector_bucket}
          disabled={!isGranted || configuring}
          onValueChange={(value) => configure({ sector_bucket: value as PulseSectorBucket })}
        >
          <SelectTrigger aria-label={t_i18n('Sector bucket')} style={{ width: 240 }}>
            <SelectValue>{t_i18n(PULSE_SECTOR_LABELS[settings.sector_bucket ?? settings.suggested_sector_bucket])}</SelectValue>
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Sector bucket')}>
            {SECTOR_VALUES.map((value) => <SelectItem key={value} value={value}>{t_i18n(PULSE_SECTOR_LABELS[value])}</SelectItem>)}
          </SelectContent>
        </Select>
      </ExperienceDetailRow>
      <ExperienceDetailRow label={t_i18n('Region bucket')}>
        <Select
          value={settings.region_bucket ?? settings.suggested_region_bucket}
          disabled={!isGranted || configuring}
          onValueChange={(value) => configure({ region_bucket: value as PulseRegionBucket })}
        >
          <SelectTrigger aria-label={t_i18n('Region bucket')} style={{ width: 240 }}>
            <SelectValue>{t_i18n(PULSE_REGION_LABELS[settings.region_bucket ?? settings.suggested_region_bucket])}</SelectValue>
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Region bucket')}>
            {REGION_VALUES.map((value) => <SelectItem key={value} value={value}>{t_i18n(PULSE_REGION_LABELS[value])}</SelectItem>)}
          </SelectContent>
        </Select>
      </ExperienceDetailRow>
      <ThreatPulsePrivacyFields
        availableScopes={settings.available_scopes}
        scopes={[...settings.scopes]}
        onScopesChange={(scopes) => configure({ scopes })}
        forcedMarkings={settings.forced_excluded_markings}
        markingOptions={markingOptions}
        excludedIds={settings.excluded_markings.map((marking) => marking.id)}
        onExcludedChange={(ids) => configure({ excluded_markings: ids })}
        disabled={!isGranted || configuring}
      />
      <ExperienceDetailRow label={t_i18n('Consent')}>
        <Text variant="content-compact">
          {settings.consent_date ? `${settings.consent_accepted_version} - ${settings.consent_user_name ?? '-'} - ${fldt(settings.consent_date)}` : '-'}
        </Text>
      </ExperienceDetailRow>
      <ExperienceDetailRow label={t_i18n('Records contributed (30 days)')}>
        <Text variant="content-compact" data-testid="threat-pulse-total-records">{n(settings.contribution.total_records)}</Text>
      </ExperienceDetailRow>
      {settings.contribution.by_type.length > 0 && (
        <ExperienceDetailRow label={t_i18n('Records by entity type')}>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
            {settings.contribution.by_type.map((item) => (
              <Chip key={item.entity_type} label={`${translateEntityType(item.entity_type)} ${n(item.records)}`} />
            ))}
          </Box>
        </ExperienceDetailRow>
      )}
      <ExperienceDetailRow label={t_i18n('Last contribution')}>
        <Text variant="content-compact">{settings.contribution.last_push_at ? fldt(settings.contribution.last_push_at) : '-'}</Text>
      </ExperienceDetailRow>
      <ExperienceDetailRow label={t_i18n('Last network refresh')}>
        <Text variant="content-compact">{settings.contribution.last_refresh_at ? fldt(settings.contribution.last_refresh_at) : '-'}</Text>
      </ExperienceDetailRow>
      <ExperienceDetailRow label={t_i18n('Contributing platforms in the network')}>
        <Text variant="content-compact">{settings.network.reachable ? (settings.network.contributors_bucket ?? '-') : t_i18n('XTM Hub is unreachable')}</Text>
      </ExperienceDetailRow>
      <ExperienceDetailRow label={t_i18n('Anonymity threshold')} divider={false}>
        <Text variant="content-compact">
          {settings.network.k_threshold ? `${settings.network.k_threshold} ${t_i18n('platforms')} - ${t_i18n('retention')} ${settings.network.retention_months} ${t_i18n('months')}` : '-'}
        </Text>
      </ExperienceDetailRow>
      {settings.contribution.last_error && (
        <Alert severity="warning" variant="outlined">{`${t_i18n('Last error')}: ${settings.contribution.last_error}`}</Alert>
      )}
    </div>
  );

  return (
    <>
      <ExperienceCard
        icon={<SensorsOutlined />}
        overline={t_i18n('Filigran Experience')}
        title={t_i18n('Threat Pulse')}
        accent={accent}
        statusChip={statusChip}
        footer={footer}
        testId="experience-threat-pulse-card"
      >
        {settings.enabled ? configuration : pitch}
      </ExperienceCard>
      {openConsent && (
        <ThreatPulseConsentDialog
          open={openConsent}
          settings={settings}
          markingOptions={markingOptions}
          onClose={() => setOpenConsent(false)}
          onAccept={({ sector, region, scopes, excludedIds }) => {
            // The privacy choices travel with the consent: nothing is contributed before they apply.
            commitConfigure({
              variables: {
                input: {
                  mode: 'contribute_and_read',
                  sector_bucket: sector,
                  region_bucket: region,
                  scopes,
                  excluded_markings: excludedIds,
                  consent_version: settings.consent_version,
                },
              },
              onCompleted: (response, errors) => {
                if ((errors && errors.length > 0) || !response?.pulseConfigure) {
                  MESSAGING$.notifyError(t_i18n('The contribution to Threat Pulse could not be enabled. Try again later.'));
                  return;
                }
                setOpenConsent(false);
              },
            });
          }}
        />
      )}
      <Dialog open={openPurge} onClose={() => setOpenPurge(false)} title={t_i18n('Purge my contributions')} size="small">
        <Text variant="content-compact">
          {t_i18n('XTM Hub deletes every contribution of this platform and recomputes the network statistics. Stop contributing as well to send nothing more.')}
        </Text>
        <DialogActions>
          <Button variant="secondary" onClick={() => setOpenPurge(false)}>{t_i18n('Cancel')}</Button>
          <Button color="error" onClick={purge} disabled={purging} data-testid="threat-pulse-purge-confirm">{t_i18n('Purge')}</Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

const ThreatPulseSettingsLoader = () => {
  // Only a user who can change the exclusions picks markings; the others read the excluded ones from the settings.
  const withMarkings = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const data = useLazyLoadQuery<ThreatPulseSettingsQuery>(threatPulseSettingsQuery, { withMarkings }, { fetchPolicy: 'network-only' });
  const markings = (data.markingDefinitions?.edges ?? []).map((edge) => edge.node);
  return <ThreatPulseSettingsComponent settingsKey={data.pulseSettings} markings={markings} />;
};

const ThreatPulseSettings = () => (
  <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
    <ThreatPulseSettingsLoader />
  </Suspense>
);

export default ThreatPulseSettings;
