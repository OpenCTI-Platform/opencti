// attributes widgets (resolved from backend)
import type { ResolvedWidgetAttribute } from '../../generated/graphql';

export const hardcodedResolvedAttributesWidgets: ResolvedWidgetAttribute[] = [
  { template_widget_name: 'reportName', data: ['[Hardcoded report name]'] },
  { template_widget_name: 'reportPublicationDate', data: ['[Hardcoded publication date]'] },
  { template_widget_name: 'reportLabels', data: ['label1', 'label2', 'label3'] },
  { template_widget_name: 'containerName', data: ['Suspicious \'UACBypassExp\' behavior was blocked on one endpoint'] },
  { template_widget_name: 'containerCreationDate', data: ['16 october 2024, 09:00'] },
  { template_widget_name: 'containerDescription', data: ['This is my **super** *description*'] },
  { template_widget_name: 'containerLabels', data: ['sentinel, detection'] },
  { template_widget_name: 'containerMarkings', data: ['TLP:RED'] },
  { template_widget_name: 'containerModificationDate', data: ['17 october 2024, 09:00'] },
  { template_widget_name: 'containerReferences', data: ['TODO list of references'] },
  { template_widget_name: 'incidentPriority', data: ['P1'] },
  { template_widget_name: 'incidentSeverity', data: ['MEDIUM'] },
  { template_widget_name: 'incidentType', data: ['intrusion'] },
];
