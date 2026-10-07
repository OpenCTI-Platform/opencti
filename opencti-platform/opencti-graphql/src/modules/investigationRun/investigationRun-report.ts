/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

// Markdown rendering of an investigation run, used for the summary Note the
// run writes into its Draft and for the "Autonomous investigation summary"
// fintel template. Every value coming from the engine or the graph is escaped,
// except the engine's summary and cited report, markdown by contract: the
// front end renders them through marked + DOMPurify.

import { confidenceLabelText, evidenceCategoryText } from './investigationRun-ach';
import type { BasicStoreEntityInvestigationRun, InvestigationEvidence, InvestigationHypothesis } from './investigationRun-types';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';

export interface InvestigationReportSections {
  executive_summary: string;
  report: string;
  timeline: string;
  hypotheses: string;
  recommendations: string;
  iocs: string;
}

const REPORT_TIMELINE_ROWS = 50;
const REPORT_IOC_ROWS = 100;

// Escape the characters that would turn a value into markdown structure.
export const escapeMarkdown = (value: string | null | undefined): string => {
  if (!value) return '';
  return value
    .replace(/\r?\n/g, ' ')
    .replace(/([\\`*_{}[\]()#+!|<>~])/g, '\\$1')
    .trim();
};

// A hypothesis no evidence assessed has no confidence: the report says so instead of inventing one.
const confidenceText = (hypothesis: InvestigationHypothesis) => (hypothesis.confidence === null || !hypothesis.confidence_label
  ? 'not assessed'
  : `${confidenceLabelText(hypothesis.confidence_label)} (${hypothesis.confidence}%)`);

const formatDate = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? escapeMarkdown(value) : date.toISOString().replace('T', ' ').slice(0, 16);
};

const isIocEvidence = (evidence: InvestigationEvidence) => {
  return !!evidence.entity_type && (evidence.entity_type === ENTITY_TYPE_INDICATOR || isStixCyberObservable(evidence.entity_type));
};

const buildExecutiveSummary = (run: BasicStoreEntityInvestigationRun) => {
  const leading = run.hypotheses.find((hypothesis) => hypothesis.rank === 1);
  const lines: string[] = [];
  if (run.summary) {
    // The engine summary is markdown by contract: kept as is, sanitized at render time.
    lines.push(run.summary);
  } else {
    lines.push(`Investigation of ${escapeMarkdown(run.subject_type)} ${escapeMarkdown(run.name)}.`);
  }
  if (leading) {
    lines.push('');
    lines.push(`**Leading hypothesis:** ${escapeMarkdown(leading.candidate_name ?? leading.candidate_id)} `
      + `(${escapeMarkdown(leading.candidate_type ?? '')}), ${confidenceText(leading)}.`);
  }
  lines.push('');
  lines.push(`Evidence items: ${run.evidence.length}. Enrichment jobs: ${run.budget.used_enrichment_jobs}. `
    + `Iterations: ${run.budget.used_iterations}.`);
  return lines.join('\n');
};

const buildTimeline = (run: BasicStoreEntityInvestigationRun) => {
  if (run.timeline.length === 0) {
    return 'No dated event was found.';
  }
  const rows = [...run.timeline]
    .sort((a, b) => a.ts.localeCompare(b.ts))
    .slice(0, REPORT_TIMELINE_ROWS)
    .map((event) => `| ${formatDate(event.ts)} | ${escapeMarkdown(event.entity_type)} | ${escapeMarkdown(event.name ?? event.entity_id)} | ${escapeMarkdown(event.event)} |`);
  return ['| Date (UTC) | Type | Entity | Event |', '| --- | --- | --- | --- |', ...rows].join('\n');
};

const buildHypotheses = (run: BasicStoreEntityInvestigationRun) => {
  if (run.hypotheses.length === 0) {
    return 'No attribution hypothesis was assessed.';
  }
  const table = [
    '| Rank | Candidate | Type | Probability | Confidence | Evidence |',
    '| --- | --- | --- | --- | --- | --- |',
    ...[...run.hypotheses]
      .sort((a, b) => a.rank - b.rank)
      .map((hypothesis) => `| ${hypothesis.rank} | ${escapeMarkdown(hypothesis.candidate_name ?? hypothesis.candidate_id)} `
        + `| ${escapeMarkdown(hypothesis.candidate_type ?? '')} | ${Math.round(hypothesis.probability * 100)}% `
        + `| ${confidenceText(hypothesis)} | ${hypothesis.evidence.length} |`),
  ];
  const details = [...run.hypotheses]
    .sort((a, b) => a.rank - b.rank)
    .map((hypothesis) => {
      const strongest = [...hypothesis.evidence]
        .sort((a, b) => b.weight * Math.abs(b.consistency) - a.weight * Math.abs(a.consistency))
        .slice(0, 5)
        .map((cell) => `  - ${cell.consistency > 0 ? '+' : ''}${cell.consistency} ${evidenceCategoryText(cell.category)}: `
          + `${escapeMarkdown(cell.evidence_name ?? cell.evidence_id)}${cell.rationale ? ` - ${escapeMarkdown(cell.rationale)}` : ''}`);
      return [`- **${escapeMarkdown(hypothesis.candidate_name ?? hypothesis.candidate_id)}**: ${escapeMarkdown(hypothesis.explanation)}`, ...strongest].join('\n');
    });
  return [...table, '', ...details].join('\n');
};

const buildRecommendations = (run: BasicStoreEntityInvestigationRun) => {
  if (run.recommendations.length === 0) {
    return 'No recommendation.';
  }
  const rows = run.recommendations.map((recommendation) => `| ${recommendation.priority} | ${escapeMarkdown(recommendation.text)} `
    + `| ${escapeMarkdown(recommendation.action_kind.replace(/_/g, ' '))} | ${escapeMarkdown(recommendation.status.replace(/_/g, ' '))} |`);
  return ['| Priority | Recommendation | Action | Status |', '| --- | --- | --- | --- |', ...rows].join('\n');
};

const buildIocs = (run: BasicStoreEntityInvestigationRun) => {
  const iocs = run.evidence.filter(isIocEvidence).slice(0, REPORT_IOC_ROWS);
  if (iocs.length === 0) {
    return 'No indicator or observable was collected.';
  }
  const rows = iocs.map((evidence) => `| ${escapeMarkdown(evidence.entity_type)} | ${escapeMarkdown(evidence.label)} | ${evidence.n ? `[${evidence.n}]` : '-'} |`);
  return ['| Type | Value | Citation |', '| --- | --- | --- |', ...rows].join('\n');
};

// The engine's cited report, followed by the sources it cites.
const buildReport = (run: BasicStoreEntityInvestigationRun) => {
  if (!run.report) {
    return 'No report was written.';
  }
  const sources = (run.report_sources ?? []).map((source) => `${source.n}. ${escapeMarkdown(source.label)}${source.href ? ` - <${encodeURI(source.href)}>` : ''}`);
  return sources.length > 0 ? [run.report, '', '**Sources**', '', ...sources].join('\n') : run.report;
};

export const buildInvestigationReportSections = (run: BasicStoreEntityInvestigationRun): InvestigationReportSections => ({
  executive_summary: buildExecutiveSummary(run),
  report: buildReport(run),
  timeline: buildTimeline(run),
  hypotheses: buildHypotheses(run),
  recommendations: buildRecommendations(run),
  iocs: buildIocs(run),
});

export const buildInvestigationNoteContent = (run: BasicStoreEntityInvestigationRun): string => {
  const sections = buildInvestigationReportSections(run);
  return [
    '## Executive summary',
    sections.executive_summary,
    '## Timeline',
    sections.timeline,
    '## Hypotheses (Analysis of Competing Hypotheses)',
    sections.hypotheses,
    '## Recommendations',
    sections.recommendations,
    '## Indicators and observables',
    sections.iocs,
  ].join('\n\n');
};
