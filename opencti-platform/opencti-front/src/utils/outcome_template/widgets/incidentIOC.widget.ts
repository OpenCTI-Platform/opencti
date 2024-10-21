import type { TemplateWidget } from '../template';

const widgetIncidentIOC: TemplateWidget = {
  name: 'Incident IOCs',
  widget: {
    type: 'list',
    id: 'widgetIncidentIOC',
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

export default widgetIncidentIOC;
