import React, { ReactNode } from 'react';
import { StixCoreObject } from '@components/widgets/WidgetCustomAttributesCard';
import FieldOrEmpty from '../../components/FieldOrEmpty';
import MarkdownDisplay from '../../components/markdownDisplay/MarkdownDisplay';
import { Stack } from '@mui/material';
import Tag from '@common/tag/Tag';
import ItemOpenVocab from '../../components/ItemOpenVocab';
import ExpandableMarkdown from '../../components/ExpandableMarkdown';

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

export const entityTypeRenderers: Record<string, EntityRenderers> = {
  Campaign: campaignRenderers,
  Report: reportRenderers,
  Grouping: groupingRenderers,
  MalwareAnalysis: malwareAnalysisRenderers,
  Incident: incidentRenderers,
};
