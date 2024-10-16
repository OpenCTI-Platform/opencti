import type { Template, TemplateWidget } from '../template';

// text //
export const templateText: Template = {
  name: 'template with simple text',
  content: '<body>\n'
    + '<h1> Main title </h1>\n'
    + '<p> Some content </p>\n'
    + '<h2> Subtitle 2 </h2>\n'
    + '<h3> Subtitle 3 </h3>\n'
    + '<p> A paragraph content </p> \n'
    + '</body> \n'
    + '</html>',
  used_variables: [],
};

// attribute //

export const templateAttribute: Template = {
  name: 'template with attributes',
  content: `<body>
    <h1> Main title </h1>
    <p> Report name: $reportName</p>
    <p> This report has been published $reportPublicationDate, and has labels: $reportLabels</p>
    </body>
    </html>`,
  used_variables: ['reportName', 'reportPublicationDate', 'reportLabels'],
};

export const widgetAttribute: TemplateWidget = {
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

// attributes widgets (resolved from backend)
export const resolvedAttributesWidgets = [
  { template_widget_name: 'reportName', data: '[Hardcoded report name]' },
  { template_widget_name: 'reportPublicationDate', data: '[Hardcoded publication date]' },
  { template_widget_name: 'reportLabels', data: 'label1, label2, label3' },
];

// list //

export const templateList: Template = {
  name: 'template list: list of locations contained in the report',
  content: '<body>\n'
    + '<h1> Main title </h1>\n'
    + '<p> Locations contained in the report: $locationsList</p>\n'
    + '</body> \n'
    + '</html>',
  used_variables: ['locationsList'],
};

export const widgetList: TemplateWidget = {
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

export const templateGraph: Template = {
  name: 'template graph (donut)',
  used_variables: ['widgetGraph'],
  content: `
  <div style="width: 600px">
    <h1>Template graph</h1>
    <div>$widgetGraph</div>
  </div>
  `,
};

export const widgetGraph: TemplateWidget = {
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

// Retrieve widgets used in the template, for now, hardcoded
export const usedTemplateWidgets: TemplateWidget[] = [widgetAttribute, widgetList, widgetGraph];
