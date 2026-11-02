import { importCaseIncident } from './case-incident';
import { importCaseRfi } from './case-rfi';
import { importCaseRft } from './case-rft';
import type { StixImporter } from '../kwargs';
import { importFeedback } from './feedback';
import { importGrouping } from './grouping';
import { importIndicator } from './indicator';
import { importNote } from './note';
import { importObservedData } from './observed-data';
import { importOpinion } from './opinion';
import { importReport } from './report';
import { importTask } from './task';

// Importers of the containers (report, note, opinion, observed-data, grouping, cases...) and indicator
export const CONTAINER_IMPORTERS: Record<string, StixImporter> = {
  note: importNote,
  'observed-data': importObservedData,
  opinion: importOpinion,
  report: importReport,
  'case-rfi': importCaseRfi,
  'x-opencti-case-rfi': importCaseRfi,
  'case-rft': importCaseRft,
  'x-opencti-case-rft': importCaseRft,
  'case-incident': importCaseIncident,
  'x-opencti-case-incident': importCaseIncident,
  feedback: importFeedback,
  'x-opencti-feedback': importFeedback,
  grouping: importGrouping,
  indicator: importIndicator,
  task: importTask,
  'x-opencti-task': importTask,
};
