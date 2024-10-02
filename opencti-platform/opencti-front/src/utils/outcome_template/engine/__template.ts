import { Widget } from '../../widget/widget';
import { TemplateWidget } from '../template';

export const templateGraph = {
  name: 'template graph',
  used_variables: ['$widgetGraph'],
  content: `
  <body>
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
