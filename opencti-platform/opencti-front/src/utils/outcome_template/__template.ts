import { ResolvedAttributesWidget, Template, TemplateWidget } from './template';
import templateIncidentCase from './__incidentCase.template';
import widgetContainerName from './widgets/containerName.widget';
import widgetContainerCreationDate from './widgets/containerCreationDate.widget';
import widgetContainerDescription from './widgets/containerDescription.widget';
import widgetContainerLabels from './widgets/containerLabels.widget';
import widgetContainerMarkings from './widgets/containerMarkings.widget';
import widgetContainerModificationDate from './widgets/containerModificationDate.widget';
import widgetContainerObservables from './widgets/containerObservables.widget';
import widgetContainerReferences from './widgets/containerReferences.widget';
import widgetIncidentIOC from './widgets/incidentIOC.widget';
import widgetIncidentPriority from './widgets/incidentPriority.widget';
import widgetIncidentSeverity from './widgets/incidentSeverity.widget';
import widgetIncidentTasksActions from './widgets/incidentTasksActions.widget';
import widgetIncidentTTP from './widgets/incidentTTP.widget';
import widgetIncidentType from './widgets/incidentType.widget';

// text //
const templateText: Template = {
  name: 'template with simple text',
  content: '<body>\n'
    + '<h1> Main title </h1>\n'
    + '<p> Some content </p>\n'
    + '<h2> Subtitle 2 </h2>\n'
    + '<h3> Subtitle 3 </h3>\n'
    + '<p> A paragraph content </p> \n'
    + '</body> \n'
    + '</html>',
  used_widgets: [],
};

// attribute //

const templateAttribute: Template = {
  name: 'template with attributes',
  content: `<body>
    <h1> Main title </h1>
    <p> Report name: $reportName</p>
    <p> This report has been published $reportPublicationDate, and has labels: $reportLabels</p>
    </body>
    </html>`,
  used_widgets: ['reportName', 'reportPublicationDate', 'reportLabels'],
};

const widgetAttribute: TemplateWidget = {
  name: 'rapportName',
  widget: {
    type: 'attribute',
    perspective: 'entities',
    id: 'widgetAttribute_id',
    parameters: {
      title: 'Report name (widget title)',
    },
    dataSelection: [
      {
        filters: {
          mode: 'and',
          filters: [{ key: 'id', values: ['CONTAINER_ID'] }],
          filterGroups: [],
        },
        attribute: 'representative.main',
        perspective: 'entities',
      },
    ],
  },
};

// list //

const templateList: Template = {
  name: 'template list: list of locations contained in the report',
  content: '<body>\n'
    + '<h1> Main title </h1>\n'
    + '<p> Locations contained in the report: $locationsList</p>\n'
    + '</body> \n'
    + '</html>',
  used_widgets: ['locationsList'],
};

const widgetList: TemplateWidget = {
  name: 'locationsList',
  widget: {
    id: 'widgetList_id',
    type: 'list',
    perspective: 'entities',
    parameters: {
      title: 'Locations contained in the report',
    },
    dataSelection: [
      {
        perspective: 'entities',
        filters: {
          mode: 'and',
          filters: [
            { key: 'entity_type', values: ['Country', 'City', 'Region', 'Position', 'Administrative-Area'] },
            { key: 'objects', values: ['CONTAINER_ID'] },
          ],
          filterGroups: [],
        },
      },
    ],
  },
};

// graph //

const templateGraph: Template = {
  name: 'template graph (donut)',
  used_widgets: ['widgetGraph'],
  content: `
  <div style="width: 600px">
    <h1>Template graph</h1>
    <div>$widgetGraph</div>
  </div>
  `,
};

const widgetGraph: TemplateWidget = {
  name: 'widgetGraph',
  widget: {
    id: 'e1853ae4-f947-4cf6-beca-f2ea6dc564d9',
    type: 'donut',
    perspective: 'relationships',
    dataSelection: [
      {
        attribute: 'entity_type',
        date_attribute: 'created_at',
        perspective: 'relationships',
        isTo: false,
        number: 100,
      },
    ],
    parameters: {
      title: 'pouet',
    },
  },
};

export const hardcodedTemplates: Template[] = [
  templateGraph,
  templateList,
  templateAttribute,
  templateText,
  templateIncidentCase,
];

export const hardcodedTemplateWidgets: TemplateWidget[] = [
  widgetAttribute,
  widgetList,
  widgetGraph,
  widgetContainerName,
  widgetContainerCreationDate,
  widgetContainerDescription,
  widgetContainerLabels,
  widgetContainerMarkings,
  widgetContainerModificationDate,
  widgetContainerObservables,
  widgetContainerReferences,
  widgetIncidentIOC,
  widgetIncidentPriority,
  widgetIncidentSeverity,
  widgetIncidentTasksActions,
  widgetIncidentTTP,
  widgetIncidentType,
];

// attributes widgets (resolved from backend)
export const resolvedAttributesWidgets: ResolvedAttributesWidget[] = [
  { template_widget_name: 'reportName', data: ['[Hardcoded report name]'] },
  { template_widget_name: 'reportPublicationDate', data: ['[Hardcoded publication date]'] },
  { template_widget_name: 'reportLabels', data: ['label1, label2, label3'] },
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
