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
  fintelTemplatesQuery,
} from './exportBundleInstanceQueries';
import { ExportBundlePlaybooksQuery$data } from './__generated__/ExportBundlePlaybooksQuery.graphql';
import { ExportBundleFormsQuery$data } from './__generated__/ExportBundleFormsQuery.graphql';
import { ExportBundleWorkspacesQuery$data } from './__generated__/ExportBundleWorkspacesQuery.graphql';
import { ExportBundleCustomViewsQuery$data } from './__generated__/ExportBundleCustomViewsQuery.graphql';
import { ExportBundleIngestionCsvsQuery$data } from './__generated__/ExportBundleIngestionCsvsQuery.graphql';
import { ExportBundleIngestionTaxiisQuery$data } from './__generated__/ExportBundleIngestionTaxiisQuery.graphql';
import { ExportBundleIngestionJsonsQuery$data } from './__generated__/ExportBundleIngestionJsonsQuery.graphql';
import { ExportBundleIngestionRsssQuery$data } from './__generated__/ExportBundleIngestionRsssQuery.graphql';
import { ExportBundleFintelTemplatesQuery$data } from './__generated__/ExportBundleFintelTemplatesQuery.graphql';

const dashboardsFilters = {
  mode: 'and',
  filters: [{ key: 'type', values: ['dashboard'], mode: 'or', operator: 'eq' }],
  filterGroups: [],
};

export const EXPORT_INSTANCE_CONFIGS: ExportInstanceConfig[] = [
  {
    entityType: 'Playbook',
    label: 'Playbooks',
    group: 'Automation',
    query: playbooksQuery,
    extractData: (data) => (data as ExportBundlePlaybooksQuery$data)?.playbooks,
  },
  {
    entityType: 'Workspace',
    label: 'Custom dashboards',
    group: 'Visualization',
    query: workspacesQuery,
    extraVariables: { filters: dashboardsFilters },
    extractData: (data) => (data as ExportBundleWorkspacesQuery$data)?.workspaces,
  },
  {
    entityType: 'CustomView',
    label: 'Custom Views',
    group: 'Visualization',
    query: customViewsQuery,
    extractData: (data) => (data as ExportBundleCustomViewsQuery$data)?.customViews,
  },
  {
    entityType: 'FintelTemplate',
    label: 'FINTEL Templates',
    group: 'Visualization',
    query: fintelTemplatesQuery,
    extractData: (data) => (data as ExportBundleFintelTemplatesQuery$data)?.fintelTemplates,
  },
  {
    entityType: 'Form',
    label: 'Forms',
    group: 'Ingestion',
    query: formsQuery,
    extractData: (data) => (data as ExportBundleFormsQuery$data)?.forms,
  },
  {
    entityType: 'IngestionCsv',
    label: 'CSV Feeds',
    group: 'Ingestion',
    query: ingestionCsvsQuery,
    extractData: (data) => (data as ExportBundleIngestionCsvsQuery$data)?.ingestionCsvs,
  },
  {
    entityType: 'IngestionTaxii',
    label: 'TAXII Feeds',
    group: 'Ingestion',
    query: ingestionTaxiisQuery,
    extractData: (data) => (data as ExportBundleIngestionTaxiisQuery$data)?.ingestionTaxiis,
  },
  {
    entityType: 'IngestionJson',
    label: 'JSON Feeds',
    group: 'Ingestion',
    query: ingestionJsonsQuery,
    extractData: (data) => (data as ExportBundleIngestionJsonsQuery$data)?.ingestionJsons,
  },
  {
    entityType: 'IngestionRss',
    label: 'RSS Feeds',
    group: 'Ingestion',
    query: ingestionRsssQuery,
    extractData: (data) => (data as ExportBundleIngestionRsssQuery$data)?.ingestionRsss,
  },
];
