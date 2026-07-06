import React, { ReactNode } from 'react';
import { StixCoreObject } from '@components/widgets/WidgetCustomAttributesCard';
import FieldOrEmpty from '../../components/FieldOrEmpty';
import { List, ListItem, Stack, Typography } from '@mui/material';
import ItemCopy from '../../components/ItemCopy';
import ListItemText from '@mui/material/ListItemText';
import ExpandablePre from '../../components/ExpandablePre';
import ItemCvssScore from 'src/components/ItemCvssScore';
import ItemSeverity from 'src/components/ItemSeverity';
import TextList from '@common/text/TextList';
import ItemOpenVocab from 'src/components/ItemOpenVocab';
import { EMPTY_VALUE } from 'src/utils/String';

type AttributeRenderer = (
  data: StixCoreObject,
  t_i18n: (s: string) => string,
  fldt: (s: unknown) => string,
) => ReactNode;

type EntityRenderers = Partial<Record<string, AttributeRenderer>>;

const getField = <T,>(data: unknown, key: string): T | undefined =>
  (data as Record<string, unknown>)[key] as T | undefined;

const empty = () => (
  <Typography>{EMPTY_VALUE}</Typography>
);

const getCvssCriticity = (score: number | null | undefined): string | null => {
  if (typeof score !== 'number' || score < 0 || score > 10) return null;
  if (score === 0.0) return 'Unknown';
  if (score <= 3.9) return 'LOW';
  if (score <= 6.9) return 'MEDIUM';
  if (score <= 8.9) return 'HIGH';
  return 'CRITICAL';
};

const makeScoreRenderer = (scoreKey: string, severityKey?: string) => {
  const renderer = (data: unknown) => {
    const score = getField<number>(data, scoreKey);
    const severity = severityKey
      ? getField<string>(data, severityKey)
      : getCvssCriticity(score ?? null) ?? undefined;
    return (
      <Stack direction="row" gap={1}>
        <ItemCvssScore score={score ?? 0} />
        <ItemSeverity severity={severity ?? null} label={severity ?? null} variant="high" />
      </Stack>
    );
  };
  renderer.displayName = `ScoreRenderer(${scoreKey})`;
  return renderer;
};

const ValueCopy = ({ value }: { value: string }) => (
  <pre><ItemCopy content={value} /></pre>
);

const makeHashRenderer = (algorithm: string) => {
  const renderer = (data: unknown) => {
    const hashes = getField<{ algorithm: string; hash: string }[]>(data, 'hashes');
    const value = hashes?.find((h) => h.algorithm === algorithm)?.hash;
    if (!value) return empty();
    return <ValueCopy value={value} />;
  };
  renderer.displayName = `HashRenderer(${algorithm})`;
  return renderer;
};

// ─── Indicator
const indicatorRenderers: EntityRenderers = {
  pattern: (data) => {
    const value = getField<string>(data, 'pattern');
    return (
      <FieldOrEmpty source={value}>
        <ExpandablePre source={value ?? ''} limit={300} />
      </FieldOrEmpty>
    );
  },
};

// ─── Threat Actor Group
const threatActorGroupRenderers: EntityRenderers = {
  sophistication: (data) => {
    const value = getField<string>(data, 'sophistication');
    return (
      <FieldOrEmpty source={value}>
        <ItemOpenVocab
          displayMode="chip"
          type="threat-actor-group-sophistication-ov"
          value={value}
        />
      </FieldOrEmpty>
    );
  },
};

// ─── Threat Actor Individual
const threatActorIndividualRenderers: EntityRenderers = {
  place_of_birth: (data) => {
    const value = getField<{ name: string }>(data, 'bornIn');
    return (
      <FieldOrEmpty source={value?.name}>
        <Typography variant="body2">{value?.name}</Typography>
      </FieldOrEmpty>
    );
  },
  sophistication: (data) => {
    const value = getField<string>(data, 'sophistication');
    return (
      <FieldOrEmpty source={value}>
        <ItemOpenVocab
          displayMode="chip"
          type="threat-actor-individual-sophistication-ov"
          value={value}
        />
      </FieldOrEmpty>
    );
  },
  ethnicity: (data) => {
    const value = getField<{ name: string }>(data, 'ethnicity');
    return (
      <FieldOrEmpty source={value?.name}>
        <Typography variant="body2">{value?.name}</Typography>
      </FieldOrEmpty>
    );
  },
  height: (data, t_i18n, fldt) => {
    const heights = getField<ReadonlyArray<{ measure?: number | null; date_seen?: string | null }>>(data, 'height');
    return (
      <FieldOrEmpty source={heights}>
        <List sx={{ py: 0 }}>
          {heights?.map((h, i) => (
            <ListItem key={i} dense divider>
              <ListItemText
                primary={h.measure != null ? `${h.measure} cm` : '-'}
                secondary={h.date_seen ? fldt(h.date_seen) : t_i18n('Unknown date')}
              />
            </ListItem>
          ))}
        </List>
      </FieldOrEmpty>
    );
  },
  weight: (data, t_i18n, fldt) => {
    const weights = getField<ReadonlyArray<{ measure?: number | null; date_seen?: string | null }>>(data, 'weight');
    return (
      <FieldOrEmpty source={weights}>
        <List sx={{ py: 0 }}>
          {weights?.map((w, i) => (
            <ListItem key={i} dense divider>
              <ListItemText
                primary={w.measure != null ? `${w.measure} kg` : '-'}
                secondary={w.date_seen ? fldt(w.date_seen) : t_i18n('Unknown date')}
              />
            </ListItem>
          ))}
        </List>
      </FieldOrEmpty>
    );
  },
};

// ─── Vulnerability
const vulnerabilityRenderers: EntityRenderers = {
  x_opencti_cvss_base_score: makeScoreRenderer('x_opencti_cvss_base_score', 'x_opencti_cvss_base_severity'),
  x_opencti_cvss_v2_base_score: makeScoreRenderer('x_opencti_cvss_v2_base_score'),
  x_opencti_cvss_v4_base_score: makeScoreRenderer('x_opencti_cvss_v4_base_score', 'x_opencti_cvss_v4_base_severity'),
  x_opencti_cvss_temporal_score: makeScoreRenderer('x_opencti_cvss_temporal_score'),
  x_opencti_cvss_v2_temporal_score: makeScoreRenderer('x_opencti_cvss_v2_temporal_score'),
  x_opencti_cwe: (data) => <TextList list={getField<string[]>(data, 'x_opencti_cwe')} />,
};

// ─── Stix Cyber Observable
const stixCyberObservableRenderers: EntityRenderers = {
  modified: (_data, _t_i18n, fldt) => {
    const value = getField<string>(_data, 'x_opencti_modified_at')
      ?? getField<string>(_data, 'updated_at');
    if (!value) return empty();
    return <Typography variant="body2">{fldt(value)}</Typography>;
  },
  created: (_data, _t_i18n, fldt) => {
    const value = getField<string>(_data, 'created_at');
    if (!value) return empty();
    return <Typography variant="body2">{fldt(value)}</Typography>;
  },
};

// ─── Artifact
const artifactRenderers: EntityRenderers = {
  description: (data) => {
    const value = getField<string>(data, 'x_opencti_description');
    if (!value) return empty();
    return <ExpandablePre source={value} limit={400} />;
  },
  modified: stixCyberObservableRenderers.modified,
  created: stixCyberObservableRenderers.created,
  x_opencti_additional_names: (data) => {
    const values = getField<string[]>(data, 'x_opencti_additional_names');
    return (
      <FieldOrEmpty source={values}>
        {values?.map((v) => <ValueCopy key={v} value={v} />)}
      </FieldOrEmpty>
    );
  },
  hash_md5: makeHashRenderer('MD5'),
  hash_sha1: makeHashRenderer('SHA-1'),
  hash_sha256: makeHashRenderer('SHA-256'),
  hash_sha512: makeHashRenderer('SHA-512'),
};

export const entityTypeRenderers: Record<string, EntityRenderers> = {
  Indicator: indicatorRenderers,
  'Threat-Actor-Individual': threatActorIndividualRenderers,
  'Threat-Actor-Group': threatActorGroupRenderers,
  Vulnerability: vulnerabilityRenderers,
  'Stix-Cyber-Observable': stixCyberObservableRenderers,
  Artifact: artifactRenderers,
};
