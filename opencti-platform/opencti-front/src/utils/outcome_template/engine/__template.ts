import { Template, TemplateWidget } from '../template';
import { Widget } from '../../widget/widget';

// text //
export const templateText = {
  name: 'Template Text',
  content: '<body>\n'
    + '<h1> Voici le titre principal </h1>\n'
    + '<p> Et voilà le texte de la page</p>\n'
    + '<h2> On crée les autres titres de la même manière </h2>\n'
    + '<h3> On peut créer jusqu\'à six niveaux de titres </h3>\n'
    + '<h4> Titre de niveau 4 </h4>\n'
    + '<h5> Titre de niveau 5 </h5>\n'
    + '<h6> Titre de niveau 6 </h6>\n'
    + '<p> Chaque titre peut contenir du texte, comme ici </p> \n'
    + '</body> \n'
    + '</html>',
  used_variables: [],
};

// attribute //

export const templateAttribute = {
  name: 'template2',
  content: '<body>\n'
    + '<h1> Titre principal </h1>\n'
    + '<p> nom du rapport: $reportName</p>\n'
    + '<p> Ce rapport, publié le $reportPublicationDate, a pour labels: $reportLabels</p>\n'
    + '</body> \n'
    + '</html>',
  used_variables: ['reportName', 'reportPublicationDate', 'reportLabels'],
};

export const widgetAttribute = {
  name: 'rapportName',
  widget: {
    type: 'attribute',
    perspective: 'entities',
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
      },
    ],
  } as Widget,
};

// attributes widgets (resolved from backend)
export const resolvedAttributesWidgets = [
  { template_widget_name: 'reportName', data: '[Hardcoded report name]' },
  { template_widget_name: 'reportPublicationDate', data: '[Hardcoded publication date]' },
  { template_widget_name: 'reportLabels', data: 'label1, label2, label3' },
];

// list //

export const templateList = {
  name: 'template3',
  content: '<body>\n'
    + '<h1> Main title </h1>\n'
    + '<p> Locations contained in the report: $locationsList</p>\n'
    + '</body> \n'
    + '</html>',
  used_variables: ['locationsList'],
};

export const widgetList = {
  name: 'locationsList',
  widget: {
    id: 'XXX',
    type: 'list',
    perspective: 'entities',
    parameters: {
      title: 'Locations contained in the report',
    },
    dataSelection: [
      {
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
  } as Widget,
};

// graph //

export const templateGraph: Template = {
  name: 'template graph',
  used_variables: ['widgetGraph'],
  content: `
  <body style="width: 800px">
    <h1>Template graph</h1>
    <div>$widgetGraph</div>
  </body>
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
