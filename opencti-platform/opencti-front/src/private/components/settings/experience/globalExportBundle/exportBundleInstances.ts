import type { ExportBundleWorkspacesQuery$data } from '../__generated__/ExportBundleWorkspacesQuery.graphql';
import type { ExportBundlePlaybooksQuery$data } from '../__generated__/ExportBundlePlaybooksQuery.graphql';
import type { ExportBundleFormsQuery$data } from '../__generated__/ExportBundleFormsQuery.graphql';
import type { ExportBundleCustomViewsQuery$data } from '../__generated__/ExportBundleCustomViewsQuery.graphql';
import type { ExportBundleIngestionCsvsQuery$data } from '../__generated__/ExportBundleIngestionCsvsQuery.graphql';
import type { ExportBundleIngestionJsonsQuery$data } from '../__generated__/ExportBundleIngestionJsonsQuery.graphql';
import type { ExportBundleIngestionRsssQuery$data } from '../__generated__/ExportBundleIngestionRsssQuery.graphql';
import type { ExportBundleIngestionTaxiisQuery$data } from '../__generated__/ExportBundleIngestionTaxiisQuery.graphql';
import type { ExportInstanceConfig } from './exportBundleInstanceTypes';
import {
  workspacesQuery,
  playbooksQuery,
  formsQuery,
  customViewsQuery,
  ingestionCsvsQuery,
  ingestionJsonsQuery,
  ingestionRsssQuery,
  ingestionTaxiisQuery,
} from './exportBundleInstanceQueries';

const dashboardsFilters = {
  mode: 'and',
  filters: [{ key: 'type', values: ['dashboard'], mode: 'or', operator: 'eq' }],
  filterGroups: [],
};

export const EXPORT_INSTANCE_CONFIGS: ExportInstanceConfig[] = [
  {
    entityType: 'Playbook',
    label: 'Playbooks',
    group: 'Ingestion',
    query: playbooksQuery,
    extractData: (data) => (data as ExportBundlePlaybooksQuery$data)?.playbooks,
  },
  {
    entityType: 'Form',
    label: 'Forms',
    group: 'Ingestion',
    query: formsQuery,
    extractData: (data) => (data as ExportBundleFormsQuery$data)?.forms,
  },
  {
    entityType: 'Workspace',
    label: 'Custom Dashboards',
    query: workspacesQuery,
    extraVariables: { filters: dashboardsFilters },
    extractData: (data) => (data as ExportBundleWorkspacesQuery$data)?.workspaces,
  },
  {
    entityType: 'CustomView',
    label: 'Custom Views',
    query: customViewsQuery,
    extractData: (data) => (data as ExportBundleCustomViewsQuery$data)?.customViews,
  },
  {
    entityType: 'IngestionCsv',
    label: 'CSV Feeds',
    group: 'Feeds',
    query: ingestionCsvsQuery,
    extractData: (data) => (data as ExportBundleIngestionCsvsQuery$data)?.ingestionCsvs,
  },
  {
    entityType: 'IngestionTaxii',
    label: 'Taxii Feeds',
    group: 'Feeds',
    query: ingestionTaxiisQuery,
    extractData: (data) => (data as ExportBundleIngestionTaxiisQuery$data)?.ingestionTaxiis,
  },
  {
    entityType: 'IngestionJson',
    label: 'JSON Feeds',
    group: 'Feeds',
    query: ingestionJsonsQuery,
    extractData: (data) => (data as ExportBundleIngestionJsonsQuery$data)?.ingestionJsons,
  },
  {
    entityType: 'IngestionRss',
    label: 'RSS Feeds',
    group: 'Feeds',
    query: ingestionRsssQuery,
    extractData: (data) => (data as ExportBundleIngestionRsssQuery$data)?.ingestionRsss,
  },
];
