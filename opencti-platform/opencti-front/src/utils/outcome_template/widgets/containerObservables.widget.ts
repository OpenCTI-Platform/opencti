import type { TemplateWidget } from '../template';

const widgetContainerObservables: TemplateWidget = {
  name: 'Container Observables',
  widget: {
    type: 'list',
    id: 'widgetContainerObservables',
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

export default widgetContainerObservables;
