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
import ListItemText from '@mui/material/ListItemText';
import ItemCopy from '../../components/ItemCopy';

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
  height: (data, fldt, t_i18n) => {
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
const vulnerabilityRenderer: EntityRenderers = {
  x_opencti_cisa_kev: (data, t_i18n) => {
    const value = (data as Record<string, unknown>).x_opencti_cisa_kev as boolean | undefined;
    return (
      <ItemBoolean
        status={value ?? false}
        label={value ? t_i18n('Yes') : t_i18n('No')}
        reverse
      />
    );
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
  encryption_algorithm: (data) => {
    const value = (data as Record<string, unknown>).mime_type as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <ValueCopy value={value} />;
  },
  decryption_key: (data) => {
    const value = (data as Record<string, unknown>).mime_type as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <ValueCopy value={value} />;
  },
  hash_md5: makeHashRenderer('MD5'),
  hash_sha1: makeHashRenderer('SHA-1'),
  hash_sha256: makeHashRenderer('SHA-256'),
  hash_sha512: makeHashRenderer('SHA-512'),
  url: (data) => {
    const value = (data as Record<string, unknown>).mime_type as string | undefined;
    if (!value) return <Typography variant="body2" sx={{ color: 'text.disabled' }}>-</Typography>;
    return <ValueCopy value={value} />;
  },
};

export const entityTypeRenderers: Record<string, EntityRenderers> = {
  Campaign: campaignRenderers,
  Report: reportRenderers,
  Grouping: groupingRenderers,
  MalwareAnalysis: malwareAnalysisRenderers,
  Incident: incidentRenderers,
  Indicator: indicatorRenderers,
  ThreatActorGroup: threatActorGroupRenderers,
  ThreatActorIndividual: threatActorIndividualRenderers,
  Malware: malwareRenderer,
  Vulnerability: vulnerabilityRenderer,
  AttackPattern: attackPatternRenderers,
  SecurityPlatform: secutityPlatformRenderers,
  StixCyberObservable: stixCyberObservableRenderers,
  Artifact: artifactRenderers,
};
