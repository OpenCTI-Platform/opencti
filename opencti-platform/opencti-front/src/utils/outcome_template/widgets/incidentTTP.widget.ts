import type { TemplateWidget } from '../template';

const widgetIncidentTTP: TemplateWidget = {
  name: 'Incident TTPs',
  widget: {
    type: 'list',
    id: 'widgetIncidentTTP',
    perspective: 'entities',
    dataSelection: [
      {
        perspective: 'entities',
        filters: {
          mode: 'and',
          filters: [
            { key: 'entity_type', values: ['Indicator'] },
            { key: 'objects', values: ['CONTAINER_ID'] },
          ],
          filterGroups: [],
        },
      },
    ],
  },
};

export default widgetIncidentTTP;
