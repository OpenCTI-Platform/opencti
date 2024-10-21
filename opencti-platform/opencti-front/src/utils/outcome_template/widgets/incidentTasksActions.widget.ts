import type { TemplateWidget } from '../template';

const widgetIncidentTasksActions: TemplateWidget = {
  name: 'Incident Tasks and Actions',
  widget: {
    type: 'list',
    id: 'widgetIncidentTasksActions',
    perspective: 'entities',
    dataSelection: [
      {
        perspective: 'entities',
        filters: {
          mode: 'and',
          filters: [
            { key: 'entity_type', values: ['Task'] },
            { key: 'objects', values: ['CONTAINER_ID'] },
          ],
          filterGroups: [],
        },
      },
    ],
  },
};

export default widgetIncidentTasksActions;
