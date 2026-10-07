import React, { Suspense, useState } from 'react';
import { fetchQuery, graphql, useFragment, useLazyLoadQuery, useRelayEnvironment } from 'react-relay';
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
  ComboboxHelperText,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  Select,
  SelectContent,
  SelectHelperText,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  Text,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
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
import {
  PULSE_CONTRIBUTION_STATUS_LABELS,
  PULSE_MODE_LABELS,
  PULSE_PUSH_ERROR_MESSAGES,
  PULSE_REGION_LABELS,
  PULSE_SECTOR_LABELS,
  pulsePlatformsBucketLabel,
} from '../../common/threat_pulse/threatPulseUtils';
import ThreatPulseDate from '../../common/threat_pulse/ThreatPulseDate';
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

// What each setting controls and what it means for what leaves the platform, under the field in the consent dialog and
// in Settings > Filigran Experience.
const PULSE_SECTOR_HELP = 'Shared with each contribution as a coarse category, never your organization\'s name. Sets the sector of the trending list, its alerts and the sector benchmark.';
const PULSE_REGION_HELP = 'Shared with each contribution as a coarse category, never your organization\'s name. The preview reads the community digest of this region.';
const PULSE_SCOPES_HELP = 'Only objects of these types are hashed and counted in the contribution and receive community data. Removing a type stops its contribution and removes the community data of its objects.';
const PULSE_EXCLUDED_MARKINGS_HELP = 'Objects with one of these markings are never contributed or looked up, in addition to the markings always excluded. Adding one removes the community data of those objects.';

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
          <ComboboxHelperText>{t_i18n(PULSE_SCOPES_HELP)}</ComboboxHelperText>
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
          <ComboboxHelperText>{t_i18n(PULSE_EXCLUDED_MARKINGS_HELP)}</ComboboxHelperText>
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

const ConsentList = ({ title, items, testId }: { title: string; items: string[]; testId: string }) => (
  <Box data-testid={testId}>
    <Text variant="content-compact-bold">{title}</Text>
    <Box component="ul" sx={{ margin: 0, marginTop: 0.5, paddingLeft: 2.5, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
      {items.map((item) => (
        <li key={item}><Text variant="content-compact">{item}</Text></li>
      ))}
    </Box>
  </Box>
);

const ThreatPulseConsentDialog = ({ open, settings, markingOptions, onClose, onAccept }: ConsentDialogProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [accepted, setAccepted] = useState(false);
  const [sector, setSector] = useState<PulseSectorBucket>(settings.sector_bucket ?? settings.suggested_sector_bucket);
  const [region, setRegion] = useState<PulseRegionBucket>(settings.region_bucket ?? settings.suggested_region_bucket);
  const [scopes, setScopes] = useState<string[]>([...settings.scopes]);
  const [excludedIds, setExcludedIds] = useState<string[]>(settings.excluded_markings.map((marking) => marking.id));
  return (
    <Dialog open={open} onClose={onClose} title={t_i18n('Contribute to Threat Pulse')} size="medium">
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }} data-testid="threat-pulse-consent-dialog">
        <ConsentList
          testId="threat-pulse-consent-shared"
          title={t_i18n('What is shared every hour')}
          items={[
            t_i18n('Keyed hashes of the indicators, attack patterns, vulnerabilities, intrusion sets, malware and tools this platform observes, changed every day by a salt'),
            t_i18n('How many times each one was created, sighted, detected or referenced that day'),
            t_i18n('The sector and the region you choose below'),
          ]}
        />
        <ConsentList
          testId="threat-pulse-consent-never"
          title={t_i18n('What never leaves this platform')}
          items={[
            t_i18n('Objects marked TLP:RED, TLP:AMBER+STRICT or PAP:RED, and the markings you exclude below'),
            t_i18n('Objects with restricted access'),
            t_i18n('Values, names, descriptions, files and the name of your organization'),
          ]}
        />
        <ConsentList
          testId="threat-pulse-consent-unlocks"
          title={t_i18n('What you unlock')}
          items={[
            t_i18n('How many platforms see each object, since when, and its 12-week and sector trends'),
            t_i18n('The full Trending in your sector list and its alerts'),
            t_i18n('The sector benchmark and the weekly briefing (Enterprise Edition)'),
          ]}
        />
        <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>
          {settings.network.k_threshold
            ? t_i18n('XTM Hub publishes a signal only once {count} platforms or more reported the same object. You can stop contributing and purge every contribution of this platform at any time; the preview stays and sends nothing.', { values: { count: settings.network.k_threshold } })
            : t_i18n('XTM Hub publishes a signal only once enough platforms reported the same object. You can stop contributing and purge every contribution of this platform at any time; the preview stays and sends nothing.')}
        </Text>
        <a href={THREAT_PULSE_DOCUMENTATION_URL} target="_blank" rel="noopener noreferrer">
          <Text variant="content-compact">{t_i18n('Read what is shared in each mode')}</Text>
        </a>
        <Select value={sector} onValueChange={(value) => setSector(value as PulseSectorBucket)}>
          <SelectLabel>{t_i18n('Sector')}</SelectLabel>
          <SelectTrigger aria-label={t_i18n('Sector')}>
            <SelectValue>{t_i18n(PULSE_SECTOR_LABELS[sector])}</SelectValue>
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Sector')}>
            {SECTOR_VALUES.map((value) => <SelectItem key={value} value={value}>{t_i18n(PULSE_SECTOR_LABELS[value])}</SelectItem>)}
          </SelectContent>
          <SelectHelperText>{t_i18n(PULSE_SECTOR_HELP)}</SelectHelperText>
        </Select>
        <Select value={region} onValueChange={(value) => setRegion(value as PulseRegionBucket)}>
          <SelectLabel>{t_i18n('Region')}</SelectLabel>
          <SelectTrigger aria-label={t_i18n('Region')}>
            <SelectValue>{t_i18n(PULSE_REGION_LABELS[region])}</SelectValue>
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Region')}>
            {REGION_VALUES.map((value) => <SelectItem key={value} value={value}>{t_i18n(PULSE_REGION_LABELS[value])}</SelectItem>)}
          </SelectContent>
          <SelectHelperText>{t_i18n(PULSE_REGION_HELP)}</SelectHelperText>
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
  const { t_i18n, fldt, fsd, n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const theme = useTheme<Theme>();
  const secondary = { color: theme.palette.text.secondary };
  const settings = useFragment(threatPulseSettingsFragment, settingsKey);
  const environment = useRelayEnvironment();
  const isGranted = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const [openConsent, setOpenConsent] = useState(false);
  const [openPurge, setOpenPurge] = useState(false);
  const [commitConfigure, configuring] = useApiMutation<ThreatPulseSettingsConfigureMutation>(threatPulseSettingsConfigureMutation);
  const [commitPurge, purging] = useApiMutation<ThreatPulseSettingsPurgeMutation>(threatPulseSettingsPurgeMutation);
  const accent = theme.palette.xtmhub?.main ?? theme.palette.designSystem.primary.main;
  const markingOptions = toMarkingOptions(markings, settings);

  const configure = (input: Partial<ConfigureInput>) => {
    commitConfigure({
      variables: { input: { mode: settings.mode, ...input } },
      onCompleted: (response, errors) => {
        if ((errors && errors.length > 0) || !response?.pulseConfigure) {
          MESSAGING$.notifyError(t_i18n('The Threat Pulse settings could not be saved. Try again later.'));
        }
      },
    });
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
        MESSAGING$.notifySuccess(t_i18n('{count, plural, one {# contribution} other {# contributions}} purged from XTM Hub', { values: { count: response.pulsePurge.deleted_records } }));
        // The purge takes the platform back to the preview and clears its statistics, which the result does not carry.
        fetchQuery<ThreatPulseSettingsQuery>(environment, threatPulseSettingsQuery, { withMarkings: false }).subscribe({});
      },
    });
  };

  // The contribution is enabled only under the current consent version: after an upgrade that changed the consent text,
  // nothing is sent until an administrator accepts the new version.
  const consentToRenew = settings.mode === 'contribute_and_read' && !settings.enabled;
  // A contributing platform reads the preview until XTM Hub accepted a contribution, and again once its contributions
  // lapsed: XTM Hub says which of the two, and its lapse wins over a local access that has not caught up yet.
  const contributing = settings.mode === 'contribute_and_read' && !consentToRenew && (settings.access === 'preview' || settings.access === 'full');
  const lapsed = contributing && settings.network.contribution_status === 'lapsed';
  const pending = contributing && settings.access === 'preview' && !lapsed;
  let statusChip = <Chip label={t_i18n('Off')} severity="neutral" />;
  if (settings.access === 'not_connected') {
    statusChip = <Chip label={t_i18n('Not connected')} severity="neutral" />;
  } else if (consentToRenew) {
    statusChip = <Chip label={t_i18n('Consent to renew - preview')} severity="medium" />;
  } else if (lapsed) {
    statusChip = <Chip label={t_i18n('Contribution lapsed - preview')} severity="medium" />;
  } else if (settings.access === 'full') {
    statusChip = <Chip label={t_i18n('Contributing')} severity="low" />;
  } else if (pending) {
    statusChip = <Chip label={t_i18n('First contribution pending - preview')} severity="info" />;
  } else if (settings.access === 'preview') {
    statusChip = <Chip label={t_i18n('Preview')} severity="info" />;
  }
  const fieldLabel = (label: string, help: string) => (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.25 }}>
      <Text variant="content-compact" style={secondary}>{label}</Text>
      <Text variant="content-compact" style={secondary}>{t_i18n(help)}</Text>
    </Box>
  );
  const contributorsLabel = pulsePlatformsBucketLabel(t_i18n, settings.network.contributors_bucket);
  const contributionStatus = settings.network.contribution_status
    ? t_i18n(PULSE_CONTRIBUTION_STATUS_LABELS[settings.network.contribution_status] ?? '')
    : '';

  const footer = isGranted ? (
    <>
      {/* The right to purge does not depend on the mode: what XTM Hub holds stays there after a stop */}
      {settings.hub_registered && (
        <Button variant="secondary" color="error" onClick={() => setOpenPurge(true)} disabled={purging} data-testid="threat-pulse-purge-button">
          {t_i18n('Purge my contributions')}
        </Button>
      )}
      {/* Opting out never waits for the new consent: a platform waiting for it can stop contributing too */}
      {settings.mode === 'contribute_and_read' && (
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
          {consentToRenew ? t_i18n('Review the new consent') : t_i18n('Contribute and unlock the full experience')}
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
        {settings.preview.last_refresh_at ? (
          <ThreatPulseDate
            date={settings.preview.last_refresh_at}
            format={(date) => t_i18n('{date} - {count, plural, one {# object} other {# objects}} in the digest', { values: { date, count: settings.preview.digest_items } })}
          />
        ) : <Text variant="content-compact">{t_i18n('Not refreshed yet')}</Text>}
      </ExperienceDetailRow>
    </div>
  );

  const pitch = (
    <>
      <ExperienceHeadline>{t_i18n('The open network early warning system')}</ExperienceHeadline>
      {consentToRenew && (
        <Alert severity="warning" variant="outlined" data-testid="threat-pulse-consent-renewal">
          {t_i18n('The Threat Pulse consent changed since this platform accepted it: nothing is sent until an administrator accepts the new version, and the preview is shown meanwhile.')}
        </Alert>
      )}
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
      {pending && (
        <Alert severity="info" variant="outlined" data-testid="threat-pulse-pending" style={{ marginBottom: theme.spacing(1) }}>
          {t_i18n('The full experience opens once XTM Hub accepts the first contribution of this platform, sent by the next hourly run with activity to share: the preview is shown until then.')}
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
            {settings.network.read_access_until
              ? t_i18n('{status} - full experience until {date}', { values: { status: contributionStatus, date: fsd(settings.network.read_access_until) } })
              : contributionStatus}
          </Text>
        </ExperienceDetailRow>
      )}
      <ExperienceDetailRow label={fieldLabel(t_i18n('Sector'), PULSE_SECTOR_HELP)}>
        <Select
          value={settings.sector_bucket ?? settings.suggested_sector_bucket}
          disabled={!isGranted || configuring}
          onValueChange={(value) => configure({ sector_bucket: value as PulseSectorBucket })}
        >
          <SelectTrigger aria-label={t_i18n('Sector')} style={{ width: 240 }}>
            <SelectValue>{t_i18n(PULSE_SECTOR_LABELS[settings.sector_bucket ?? settings.suggested_sector_bucket])}</SelectValue>
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Sector')}>
            {SECTOR_VALUES.map((value) => <SelectItem key={value} value={value}>{t_i18n(PULSE_SECTOR_LABELS[value])}</SelectItem>)}
          </SelectContent>
        </Select>
      </ExperienceDetailRow>
      <ExperienceDetailRow label={fieldLabel(t_i18n('Region'), PULSE_REGION_HELP)}>
        <Select
          value={settings.region_bucket ?? settings.suggested_region_bucket}
          disabled={!isGranted || configuring}
          onValueChange={(value) => configure({ region_bucket: value as PulseRegionBucket })}
        >
          <SelectTrigger aria-label={t_i18n('Region')} style={{ width: 240 }}>
            <SelectValue>{t_i18n(PULSE_REGION_LABELS[settings.region_bucket ?? settings.suggested_region_bucket])}</SelectValue>
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Region')}>
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
          {settings.consent_date
            ? t_i18n('Version {version}, accepted by {user} on {date}', { values: { version: settings.consent_accepted_version ?? '', user: settings.consent_user_name ?? t_i18n('a former user'), date: fldt(settings.consent_date) } })
            : t_i18n('Not given yet')}
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
        {settings.contribution.last_push_at
          ? <ThreatPulseDate date={settings.contribution.last_push_at} />
          : <Text variant="content-compact">{t_i18n('None yet')}</Text>}
      </ExperienceDetailRow>
      <ExperienceDetailRow label={t_i18n('Last network refresh')}>
        {settings.contribution.last_refresh_at
          ? <ThreatPulseDate date={settings.contribution.last_refresh_at} />
          : <Text variant="content-compact">{t_i18n('None yet')}</Text>}
      </ExperienceDetailRow>
      {(!settings.network.reachable || contributorsLabel) && (
        <ExperienceDetailRow label={t_i18n('Contributing platforms in the network')}>
          <Text variant="content-compact">{settings.network.reachable ? contributorsLabel : t_i18n('XTM Hub is unreachable')}</Text>
        </ExperienceDetailRow>
      )}
      {settings.network.k_threshold ? (
        <ExperienceDetailRow label={t_i18n('Anonymity threshold')} divider={false}>
          <Text variant="content-compact">
            {t_i18n('{count} platforms - contributions kept {months} months', { values: { count: settings.network.k_threshold, months: settings.network.retention_months ?? 0 } })}
          </Text>
        </ExperienceDetailRow>
      ) : null}
      {settings.contribution.last_error && (
        <Alert severity="warning" variant="outlined" data-testid="threat-pulse-last-error">
          {t_i18n(PULSE_PUSH_ERROR_MESSAGES[settings.contribution.last_error] ?? PULSE_PUSH_ERROR_MESSAGES.unexpected)}
        </Alert>
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
