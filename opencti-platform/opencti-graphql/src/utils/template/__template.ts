// text //
import type { Template } from '../../generated/graphql';
import { templateIncidentCase } from './__incidentCase.template';

// templates //

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
  used_template_widgets_names: [],
};

const templateAttribute: Template = {
  name: 'template with attributes',
  content: `<body>
    <h1> Main title </h1>
    <p> Report name: $reportName</p>
    <p> This report has been published $reportPublicationDate, and has labels: $reportLabels</p>
    </body>
    </html>`,
  used_template_widgets_names: ['reportName', 'reportPublicationDate', 'reportLabels'],
};

const templateList: Template = {
  name: 'template list: list of locations contained in the report',
  content: '<body>\n'
    + '<h1> Main title </h1>\n'
    + '<p> Locations contained in the report: $locationsList</p>\n'
    + '</body> \n'
    + '</html>',
  used_template_widgets_names: ['locationsList'],
};

const templateGraph: Template = {
  name: 'template graph (donut)',
  used_template_widgets_names: ['widgetGraph'],
  content: `
  <div style="width: 600px">
    <h1>Template graph</h1>
    <div>$widgetGraph</div>
  </div>
  `,
};

export const usedTemplates: Template[] = [templateText, templateAttribute, templateList, templateGraph, templateIncidentCase];
