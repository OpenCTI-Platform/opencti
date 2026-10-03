import type { FintelTemplateAddInput, FintelTemplateWidgetAddInput } from '../../generated/graphql';
import { SELF_ID } from './__fintelTemplateWidgets';

// Built-in template rendering the latest Case Autopilot investigation of a
// case. The sections are markdown computed from the run data by the
// platform (investigationRun-report.ts) and sanitized when rendered.
export const INVESTIGATION_SUMMARY_TEMPLATE_NAME = 'Autonomous investigation summary';
export const INVESTIGATION_SUMMARY_TEMPLATE_TYPES = ['Case-Incident', 'Case-Rfi', 'Case-Rft'];

export const widgetInvestigationSummaryAttributes: FintelTemplateWidgetAddInput = {
  variable_name: 'widgetInvestigationSummary',
  widget: {
    type: 'attribute',
    perspective: null,
    dataSelection: [{
      columns: [
        { label: 'Representative', attribute: 'representative.main', variableName: 'representative' },
        { label: 'Creation date', attribute: 'created_at', displayStyle: 'text', variableName: 'creationDate' },
        { label: 'Investigation status', attribute: 'latestInvestigationRun.run_status', variableName: 'investigationStatus' },
        { label: 'Investigation completion date', attribute: 'latestInvestigationRun.completed_at', variableName: 'investigationCompletionDate' },
        { label: 'Investigation executive summary', attribute: 'latestInvestigationRun.report.executive_summary', variableName: 'investigationExecutiveSummary' },
        { label: 'Investigation timeline', attribute: 'latestInvestigationRun.report.timeline', variableName: 'investigationTimeline' },
        { label: 'Investigation hypotheses', attribute: 'latestInvestigationRun.report.hypotheses', variableName: 'investigationHypotheses' },
        { label: 'Investigation recommendations', attribute: 'latestInvestigationRun.report.recommendations', variableName: 'investigationRecommendations' },
        { label: 'Investigation indicators of compromise', attribute: 'latestInvestigationRun.report.iocs', variableName: 'investigationIocs' },
      ],
      instance_id: SELF_ID,
    }],
    parameters: {
      title: 'Case Autopilot investigation of the case',
      description: 'Sections of the latest Case Autopilot investigation run of the case.',
    },
  },
};

const template_content = `
<div>
  <h2>Autonomous investigation summary: $representative</h2>
  <p><em>Generated from the latest Case Autopilot investigation of this case ($investigationStatus, $investigationCompletionDate). Review every section before dissemination.</em></p>

  <h3>1. Executive summary</h3>
  <div>$investigationExecutiveSummary</div>

  <h3>2. Timeline</h3>
  <div>$investigationTimeline</div>

  <div class="page-break" style="page-break-after:always;">
    <span style="display:none;">&nbsp;</span>
  </div>

  <h3>3. Hypotheses (Analysis of Competing Hypotheses)</h3>
  <div>$investigationHypotheses</div>

  <h3>4. Recommendations</h3>
  <div>$investigationRecommendations</div>

  <div class="page-break" style="page-break-after:always;">
    <span style="display:none;">&nbsp;</span>
  </div>

  <h3>5. Indicators of compromise</h3>
  <div>$investigationIocs</div>
</div>
`;

export const generateFintelTemplateInvestigationSummary = (containerType: string): FintelTemplateAddInput => ({
  name: INVESTIGATION_SUMMARY_TEMPLATE_NAME,
  description: 'Executive summary, timeline, competing hypotheses, recommendations and indicators of the latest Case Autopilot investigation.',
  template_content,
  start_date: '1970-01-01T00:00:00Z',
  settings_types: [containerType],
  default: false,
  fintel_template_widgets: [widgetInvestigationSummaryAttributes],
});
