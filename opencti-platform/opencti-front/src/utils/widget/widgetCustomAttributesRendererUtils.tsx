import React, { ReactNode } from 'react';
import { StixCoreObject } from '@components/widgets/WidgetCustomAttributesCard';
import FieldOrEmpty from '../../components/FieldOrEmpty';
import MarkdownDisplay from '../../components/markdownDisplay/MarkdownDisplay';
import { List, ListItem, Stack, Typography } from '@mui/material';
import Tag from '@common/tag/Tag';
import ItemOpenVocab from '../../components/ItemOpenVocab';
import ExpandableMarkdown from '../../components/ExpandableMarkdown';
import ExpandablePre from '../../components/ExpandablePre';
import ItemScore from '../../components/ItemScore';
import ItemBoolean from '../../components/ItemBoolean';
import ItemCopy from '../../components/ItemCopy';
import ListItemText from '@mui/material/ListItemText';
import ItemCvssScore from 'src/components/ItemCvssScore';
import ItemSeverity from 'src/components/ItemSeverity';
import TextList from '@common/text/TextList';

type AttributeRenderer = (
  data: StixCoreObject,
  t_i18n: (s: string) => string,
  fldt: (s: unknown) => string,
) => ReactNode;

type EntityRenderers = Partial<Record<string, AttributeRenderer>>;

// ─── Campaign
const campaignRenderers: EntityRenderers = {
  objective: (data) => {
    const objective = 'objective' in data
      ? (data as { objective?: string }).objective
      : undefined;
    return (
      <FieldOrEmpty source={objective}>
        <MarkdownDisplay
          content={objective ?? ''}
          remarkGfmPlugin={true}
          commonmark={true}
        />
      </FieldOrEmpty>
    );
  },
};

// ─── Report
const reportRenderers: EntityRenderers = {
  report_types: (data) => {
    const reportTypes = 'report_types' in data
      ? (data as { report_types?: string[] }).report_types
      : undefined;
    return (
      <FieldOrEmpty source={reportTypes}>
        <Stack direction="row" flexWrap="wrap" gap={1}>
          {reportTypes?.map((reportType) => (
            <Tag key={reportType} label={reportType} />
          ))}
        </Stack>
      </FieldOrEmpty>
    );
  },
};

// ─── Grouping
const groupingRenderers: EntityRenderers = {
  context: (data) => {
    const context = 'context' in data
      ? (data as { context?: string }).context
      : undefined;
    return (
      <ItemOpenVocab
        displayMode="chip"
        type="grouping-context-ov"
        value={context}
      />
    );
  },
};

// ─── Malware-Analysis
const malwareAnalysisRenderers: EntityRenderers = {
  product: (data) => {
    const product = 'product' in data
      ? (data as { product?: string }).product
      : undefined;
    return (
      <FieldOrEmpty source={product}>
        <ExpandableMarkdown source={product ?? ''} limit={300} />
      </FieldOrEmpty>
    );
  },
  result: (data) => {
    const result = 'result' in data
      ? (data as { result?: string }).result
      : undefined;
    return (
      <FieldOrEmpty source={result}>
        <Tag label={result ?? ''} />
      </FieldOrEmpty>
    );
  },
  result_name: (data) => {
    const resultName = 'result_name' in data
      ? (data as { result_name?: string }).result_name
      : undefined;
    return (
      <FieldOrEmpty source={resultName}>
        <ExpandableMarkdown source={resultName ?? ''} limit={300} />
      </FieldOrEmpty>
    );
  },
  modules: (data) => {
    const modules = 'modules' in data
      ? (data as { modules?: string[] }).modules
      : undefined;
    return (
      <FieldOrEmpty source={modules}>
        <Stack direction="row" flexWrap="wrap" gap={1}>
          {modules?.map((module) => (
            <Tag key={module} label={module} />
          ))}
        </Stack>
      </FieldOrEmpty>
    );
  },
  configuration_version: (data) => {
    const configVersion = 'configuration_version' in data
      ? (data as { configuration_version?: string }).configuration_version
      : undefined;
    return (
      <FieldOrEmpty source={configVersion}>
        <ExpandableMarkdown source={configVersion ?? ''} limit={300} />
      </FieldOrEmpty>
    );
  },
  analysis_engine_version: (data) => {
    const engineVersion = 'analysis_engine_version' in data
      ? (data as { analysis_engine_version?: string }).analysis_engine_version
      : undefined;
    return (
      <FieldOrEmpty source={engineVersion}>
        <ExpandableMarkdown source={engineVersion ?? ''} limit={300} />
      </FieldOrEmpty>
    );
  },
  analysis_definition_version: (data) => {
    const defVersion = 'analysis_definition_version' in data
      ? (data as { analysis_definition_version?: string }).analysis_definition_version
      : undefined;
    return (
      <FieldOrEmpty source={defVersion}>
        <ExpandableMarkdown source={defVersion ?? ''} limit={300} />
      </FieldOrEmpty>
    );
  },
};

// ─── Incident
const incidentRenderers: EntityRenderers = {
  source: (data) => {
    const source = 'source' in data
      ? (data as { source?: string }).source
      : undefined;
    return (
      <FieldOrEmpty source={source}>
        <Tag label={source ?? ''} />
      </FieldOrEmpty>
    );
  },
  objective: (data) => {
    const objective = 'objective' in data
      ? (data as { objective?: string }).objective
      : undefined;
    return (
      <FieldOrEmpty source={objective}>
        <ExpandableMarkdown source={objective ?? ''} limit={100} />
      </FieldOrEmpty>
    );
  },
};

// ─── Indicator
const indicatorRenderers: EntityRenderers = {
  pattern: (data) => {
    const pattern = (data as Record<string, unknown>).pattern as string | undefined;
    return (
      <FieldOrEmpty source={pattern}>
        <ExpandablePre source={pattern ?? ''} limit={300} />
      </FieldOrEmpty>
    );
  },
  x_opencti_score: (data) => {
    const score = (data as Record<string, unknown>).x_opencti_score as number | undefined;
    return <ItemScore score={score ?? null} />;
  },
  x_opencti_detection: (data, t_i18n) => {
    const detection = (data as Record<string, unknown>).x_opencti_detection as boolean | undefined;
    return (
      <ItemBoolean
        status={detection ?? false}
        label={detection ? t_i18n('Yes') : t_i18n('No')}
      />
    );
  },
  x_opencti_main_observable_type: (data) => {
    const obsType = (data as Record<string, unknown>).x_opencti_main_observable_type as string | undefined;
    return (
      <ItemOpenVocab
        displayMode="chip"
        type="observable_types_ov"
        value={obsType}
      />
    );
  },
  x_mitre_platforms_indicator: (data) => {
    const value = (data as Record<string, unknown>).x_mitre_platforms_indicator as string[] | undefined;
    return (
      <FieldOrEmpty source={value}>
        <Stack direction="row" flexWrap="wrap" gap={1}>
          {value?.map((platform) => (
            <Tag key={platform} label={platform} />
          ))}
        </Stack>
      </FieldOrEmpty>
    );
  },
};

// ─── Threat Actor Group and Individual
const threatActorGroupRenderers: EntityRenderers = {
  sophistication: (data) => {
    const value = (data as Record<string, unknown>).sophistication as string | undefined;
    return (
      <FieldOrEmpty source={value}>
        <ItemOpenVocab
          type="threat-actor-group-sophistication-ov"
          value={value}
        />
      </FieldOrEmpty>
    );
  },
  resource_level: (data) => {
    const value = (data as Record<string, unknown>).resource_level as string | undefined;
    return (
      <FieldOrEmpty source={value}>
        <ItemOpenVocab
          type="attack-resource-level-ov"
          value={value}
        />
      </FieldOrEmpty>
    );
  },

};

// ─── Threat Actor Group and Individual
const threatActorIndividualRenderers: EntityRenderers = {
  sophistication: (data) => {
    const value = (data as Record<string, unknown>).sophistication as string | undefined;
    return (
      <FieldOrEmpty source={value}>
        <ItemOpenVocab
          type="threat-actor-individual-sophistication-ov"
          value={value}
        />
      </FieldOrEmpty>
    );
  },
  place_of_birth: (data) => {
    const value = (data as Record<string, unknown>).bornIn as { name: string } | undefined;
    return (
      <FieldOrEmpty source={value?.name}>
        <Typography variant="body2">{value?.name}</Typography>
      </FieldOrEmpty>
    );
  },
  ethnicity: (data) => {
    const value = (data as Record<string, unknown>).ethnicity as { name: string } | undefined;
    return (
      <FieldOrEmpty source={value?.name}>
        <Typography variant="body2">{value?.name}</Typography>
      </FieldOrEmpty>
    );
  },
  height: (data, t_i18n, fldt) => {
    const heights = (data as Record<string, unknown>).height as
      | ReadonlyArray<{ measure?: number | null; date_seen?: string | null }>
      | null
      | undefined;
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
    const weights = (data as Record<string, unknown>).weight as
      | ReadonlyArray<{ measure?: number | null; date_seen?: string | null }>
      | null
      | undefined;
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
  date_of_birth: (data, _, fldt) => {
    const value = (data as Record<string, unknown>).date_of_birth as string | undefined;
    if (!value) {
      return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    }
    return <Typography variant="body2">{fldt(value)}</Typography>;
  },
  resource_level: threatActorGroupRenderers.resource_level,
};

// ─── Malware
const malwareRenderer: EntityRenderers = {
  is_family: (data) => {
    const value = (data as Record<string, unknown>).is_family as boolean | undefined;
    return (
      <ItemBoolean
        status={value ?? false}
        label={value ? 'Yes' : 'No'}
      />
    );
  },
};

// ─── Vulnerability
const getCvssCriticity = (score: number | null | undefined): string | null => {
  if (typeof score !== 'number' || score < 0 || score > 10) return null;
  if (score === 0.0) return 'Unknown';
  if (score <= 3.9) return 'LOW';
  if (score <= 6.9) return 'MEDIUM';
  if (score <= 8.9) return 'HIGH';
  return 'CRITICAL';
};

const makeScoreRenderer = (scoreKey: string, severityKey?: string) => {
  const renderer = (data: Record<string, unknown>, _t_i18n: unknown) => {
    const score = data[scoreKey] as number | undefined;
    const severity = severityKey
      ? data[severityKey] as string | undefined
      : getCvssCriticity(score ?? null);
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

const makeTagRenderer = (key: string) => {
  const renderer = (data: Record<string, unknown>) => {
    const value = data[key] as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <Tag label={value} />;
  };
  renderer.displayName = `TagRenderer(${key})`;
  return renderer;
};

const vulnerabilityRenderers: EntityRenderers = {
  // ── Scores
  x_opencti_cvss_base_score: makeScoreRenderer('x_opencti_cvss_base_score', 'x_opencti_cvss_base_severity'),
  x_opencti_cvss_v2_base_score: makeScoreRenderer('x_opencti_cvss_v2_base_score'),
  x_opencti_cvss_v4_base_score: makeScoreRenderer('x_opencti_cvss_v4_base_score', 'x_opencti_cvss_v4_base_severity'),
  x_opencti_cvss_temporal_score: makeScoreRenderer('x_opencti_cvss_temporal_score'),
  x_opencti_cvss_v2_temporal_score: makeScoreRenderer('x_opencti_cvss_v2_temporal_score'),
  x_opencti_cvss_base_severity: makeTagRenderer('x_opencti_cvss_base_severity'),
  x_opencti_cvss_v4_base_severity: makeTagRenderer('x_opencti_cvss_v4_base_severity'),

  // ── Vectors
  x_opencti_cvss_vector_string: makeTagRenderer('x_opencti_cvss_vector_string'),
  x_opencti_cvss_v2_vector_string: makeTagRenderer('x_opencti_cvss_v2_vector_string'),
  x_opencti_cvss_v4_vector_string: makeTagRenderer('x_opencti_cvss_v4_vector_string'),

  // ── CVSS V3 metrics
  x_opencti_cvss_attack_vector: makeTagRenderer('x_opencti_cvss_attack_vector'),
  x_opencti_cvss_attack_complexity: makeTagRenderer('x_opencti_cvss_attack_complexity'),
  x_opencti_cvss_privileges_required: makeTagRenderer('x_opencti_cvss_privileges_required'),
  x_opencti_cvss_user_interaction: makeTagRenderer('x_opencti_cvss_user_interaction'),
  x_opencti_cvss_scope: makeTagRenderer('x_opencti_cvss_scope'),
  x_opencti_cvss_confidentiality_impact: makeTagRenderer('x_opencti_cvss_confidentiality_impact'),
  x_opencti_cvss_integrity_impact: makeTagRenderer('x_opencti_cvss_integrity_impact'),
  x_opencti_cvss_availability_impact: makeTagRenderer('x_opencti_cvss_availability_impact'),
  x_opencti_cvss_exploit_code_maturity: makeTagRenderer('x_opencti_cvss_exploit_code_maturity'),
  x_opencti_cvss_remediation_level: makeTagRenderer('x_opencti_cvss_remediation_level'),
  x_opencti_cvss_report_confidence: makeTagRenderer('x_opencti_cvss_report_confidence'),

  // ── CVSS V2 metrics
  x_opencti_cvss_v2_access_vector: makeTagRenderer('x_opencti_cvss_v2_access_vector'),
  x_opencti_cvss_v2_access_complexity: makeTagRenderer('x_opencti_cvss_v2_access_complexity'),
  x_opencti_cvss_v2_authentication: makeTagRenderer('x_opencti_cvss_v2_authentication'),
  x_opencti_cvss_v2_confidentiality_impact: makeTagRenderer('x_opencti_cvss_v2_confidentiality_impact'),
  x_opencti_cvss_v2_integrity_impact: makeTagRenderer('x_opencti_cvss_v2_integrity_impact'),
  x_opencti_cvss_v2_availability_impact: makeTagRenderer('x_opencti_cvss_v2_availability_impact'),
  x_opencti_cvss_v2_exploitability: makeTagRenderer('x_opencti_cvss_v2_exploitability'),
  x_opencti_cvss_v2_remediation_level: makeTagRenderer('x_opencti_cvss_v2_remediation_level'),
  x_opencti_cvss_v2_report_confidence: makeTagRenderer('x_opencti_cvss_v2_report_confidence'),

  // ── CVSS V4 metrics
  x_opencti_cvss_v4_attack_vector: makeTagRenderer('x_opencti_cvss_v4_attack_vector'),
  x_opencti_cvss_v4_attack_complexity: makeTagRenderer('x_opencti_cvss_v4_attack_complexity'),
  x_opencti_cvss_v4_attack_requirements: makeTagRenderer('x_opencti_cvss_v4_attack_requirements'),
  x_opencti_cvss_v4_privileges_required: makeTagRenderer('x_opencti_cvss_v4_privileges_required'),
  x_opencti_cvss_v4_user_interaction: makeTagRenderer('x_opencti_cvss_v4_user_interaction'),
  x_opencti_cvss_v4_confidentiality_impact_v: makeTagRenderer('x_opencti_cvss_v4_confidentiality_impact_v'),
  x_opencti_cvss_v4_confidentiality_impact_s: makeTagRenderer('x_opencti_cvss_v4_confidentiality_impact_s'),
  x_opencti_cvss_v4_integrity_impact_v: makeTagRenderer('x_opencti_cvss_v4_integrity_impact_v'),
  x_opencti_cvss_v4_integrity_impact_s: makeTagRenderer('x_opencti_cvss_v4_integrity_impact_s'),
  x_opencti_cvss_v4_availability_impact_v: makeTagRenderer('x_opencti_cvss_v4_availability_impact_v'),
  x_opencti_cvss_v4_availability_impact_s: makeTagRenderer('x_opencti_cvss_v4_availability_impact_s'),
  x_opencti_cvss_v4_exploit_maturity: makeTagRenderer('x_opencti_cvss_v4_exploit_maturity'),
  x_opencti_cisa_kev: (data, t_i18n) => {
    const value = data.x_opencti_cisa_kev as boolean | undefined;
    if (value === undefined || value === null) {
      return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    }
    return (
      <ItemBoolean
        status={value}
        label={value ? (t_i18n as (s: string) => string)('Yes') : (t_i18n as (s: string) => string)('No')}
        reverse
      />
    );
  },
  modified: (_data, _t_i18n, fldt) => {
    const value = (_data as Record<string, unknown>).modified as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <Typography variant="body2">{(fldt as (s: unknown) => string)(value)}</Typography>;
  },
  x_opencti_epss_score: (data) => {
    const value = data.x_opencti_epss_score as number | undefined;
    if (value === undefined || value === null) {
      return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    }
    return <Tag label={String(value)} />;
  },
  x_opencti_epss_percentile: (data) => {
    const value = data.x_opencti_epss_percentile as number | undefined;
    if (value === undefined || value === null) {
      return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    }
    return <Tag label={String(value)} />;
  },
  x_opencti_cwe: (data) => {
    const value = data.x_opencti_cwe as string[] | undefined;
    return <TextList list={value} />;
  },
  x_opencti_first_seen_active: (data, _t_i18n, fldt) => {
    const value = data.x_opencti_first_seen_active as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <Typography variant="body2">{(fldt as (s: unknown) => string)(value)}</Typography>;
  },
};

// ─── Attack Pattern
const attackPatternRenderers: EntityRenderers = {
  x_mitre_detection: (data) => {
    const value = (data as Record<string, unknown>).x_mitre_detection as string | undefined;
    if (!value) {
      return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    }
    return <ExpandableMarkdown source={value} limit={400} />;
  },
  x_mitre_platforms_attack_pattern: (data) => {
    const value = (data as Record<string, unknown>).x_mitre_platforms_attack_pattern as string[] | undefined;
    return (
      <FieldOrEmpty source={value}>
        <Stack direction="row" flexWrap="wrap" gap={1}>
          {value?.map((platform) => (
            <Tag key={platform} label={platform} />
          ))}
        </Stack>
      </FieldOrEmpty>
    );
  },
};

// ─── Security Platform
const secutityPlatformRenderers: EntityRenderers = {
  security_platform_type: (data) => {
    const value = (data as Record<string, unknown>).security_platform_type as string | undefined;
    if (!value) {
      return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    }
    return <Tag label={value} />;
  },
};

// ─── Stix Cyber Observable
const stixCyberObservableRenderers: EntityRenderers = {
  observable_value: (data) => {
    const value = (data as Record<string, unknown>).observable_value as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <Typography variant="body2">{value}</Typography>;
  },
  modified: (_data, _t_i18n, fldt) => {
    const value = (_data as Record<string, unknown>).x_opencti_modified_at as string | undefined
      ?? (_data as Record<string, unknown>).updated_at as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <Typography variant="body2">{fldt(value)}</Typography>;
  },
  created: (_data, _t_i18n, fldt) => {
    const value = (_data as Record<string, unknown>).created_at as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <Typography variant="body2">{fldt(value)}</Typography>;
  },
};

// ─── Artifact
const ValueCopy = ({ value }: { value: string }) => {
  return (
    <pre>
      <ItemCopy content={value} />
    </pre>
  );
};

const makeHashRenderer = (algorithm: string) => {
  const HashRenderer = (data: unknown) => {
    const hashes = (data as Record<string, unknown>).hashes as { algorithm: string; hash: string }[] | undefined;
    const value = hashes?.find((h) => h.algorithm === algorithm)?.hash;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <ValueCopy value={value} />;
  };
  HashRenderer.displayName = `HashRenderer_${algorithm}`;
  return HashRenderer;
};

const artifactRenderers: EntityRenderers = {
  description: (data) => {
    const value = (data as Record<string, unknown>).x_opencti_description as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <ExpandableMarkdown source={value} limit={400} />;
  },
  modified: (_data, _t_i18n, fldt) => {
    const value = (_data as Record<string, unknown>).x_opencti_modified_at as string | undefined
      ?? (_data as Record<string, unknown>).updated_at as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <Typography variant="body2">{fldt(value)}</Typography>;
  },
  created: (_data, _t_i18n, fldt) => {
    const value = (_data as Record<string, unknown>).created_at as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <Typography variant="body2">{fldt(value)}</Typography>;
  },
  encryption_algorithm: (data) => {
    const value = (data as Record<string, unknown>).encryption_algorithm as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <ValueCopy value={value} />;
  },
  decryption_key: (data) => {
    const value = (data as Record<string, unknown>).decryption_key as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <ValueCopy value={value} />;
  },
  url: (data) => {
    const value = (data as Record<string, unknown>).url as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <ValueCopy value={value} />;
  },
  mime_type: (data) => {
    const value = (data as Record<string, unknown>).mime_type as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <ValueCopy value={value} />;
  },
  x_opencti_additional_names: (data) => {
    const values = (data as Record<string, unknown>).x_opencti_additional_names as string[] | undefined;
    return (
      <FieldOrEmpty source={values}>
        {values?.map((v) => (
          <ValueCopy key={v} value={v} />
        ))}
      </FieldOrEmpty>
    );
  },
  hash_md5: makeHashRenderer('MD5'),
  hash_sha1: makeHashRenderer('SHA-1'),
  hash_sha256: makeHashRenderer('SHA-256'),
  hash_sha512: makeHashRenderer('SHA-512'),
};

export const entityTypeRenderers: Record<string, EntityRenderers> = {
  Campaign: campaignRenderers,
  Report: reportRenderers,
  Grouping: groupingRenderers,
  'Malware-Analysis': malwareAnalysisRenderers,
  Incident: incidentRenderers,
  Indicator: indicatorRenderers,
  'Threat-Actor-Group': threatActorGroupRenderers,
  'Threat-Actor-Individual': threatActorIndividualRenderers,
  Malware: malwareRenderer,
  Vulnerability: vulnerabilityRenderers,
  'Attack-Pattern': attackPatternRenderers,
  SecurityPlatform: secutityPlatformRenderers,
  'Stix-Cyber-Observable': stixCyberObservableRenderers,
  Artifact: artifactRenderers,
};
