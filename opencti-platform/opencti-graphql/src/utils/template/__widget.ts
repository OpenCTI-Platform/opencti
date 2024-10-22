import type { FilterGroup, TemplateWidget } from '../../generated/graphql';

// hardcoded widgets

const widgetContainerCreationDate: TemplateWidget = {
  name: 'Container Creation Date',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerCreationDate',
    perspective: null,
    dataSelection: [{
      attribute: 'created_at',
    }],
  }),
};

const widgetContainerDescription: TemplateWidget = {
  name: 'Container Description',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerDescription',
    perspective: null,
    dataSelection: [{
      attribute: 'description',
    }],
  }),
};

const widgetContainerLabels: TemplateWidget = {
  name: 'Container Labels',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerLabels',
    perspective: null,
    dataSelection: [{
      attribute: 'objectLabel.value',
    }],
  }),
};

const widgetContainerMarkings: TemplateWidget = {
  name: 'Container Markings',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerMarkings',
    perspective: null,
    dataSelection: [{
      attribute: 'objectMarking.definition',
    }],
  }),
};

const widgetContainerModificationDate: TemplateWidget = {
  name: 'Container Modification Date',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerModificationDate',
    perspective: null,
    dataSelection: [{
      attribute: 'modified',
    }],
  }),
};

const widgetContainerName: TemplateWidget = {
  name: 'Container Name',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerName',
    perspective: null,
    dataSelection: [{
      attribute: 'name',
    }],
  }),
};

const widgetContainerIndicators: TemplateWidget = {
  name: 'Container Indicators',
  widget: JSON.stringify({
    type: 'list',
    id: 'widgetContainerIndicators',
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
        } as FilterGroup,
      },
    ],
  }),
};

const widgetContainerReferences: TemplateWidget = {
  name: 'Container References',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerReferences',
    perspective: null,
    dataSelection: [],
  }),
};

const widgetLocationsList: TemplateWidget = {
  name: 'locationsList',
  widget: JSON.stringify({
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
        } as FilterGroup,
      },
    ],
  }),
};

const widgetDonut: TemplateWidget = {
  name: 'widgetGraph',
  widget: JSON.stringify({
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
  }),
};

const widgetIncidentIOC: TemplateWidget = {
  name: 'Incident IOCs',
  widget: JSON.stringify({
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
        } as FilterGroup,
      },
    ],
  }),
};

const widgetIncidentPriority: TemplateWidget = {
  name: 'Incident Priority',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetIncidentPriority',
    perspective: null,
    dataSelection: [{
      attribute: 'priority',
    }],
  }),
};

const widgetIncidentSeverity: TemplateWidget = {
  name: 'Incident Severity',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetIncidentSeverity',
    perspective: null,
    dataSelection: [{
      attribute: 'severity',
    }],
  }),
};

const widgetIncidentTasksActions: TemplateWidget = {
  name: 'Incident Tasks and Actions',
  widget: JSON.stringify({
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
        } as FilterGroup,
      },
    ],
  }),
};

const widgetIncidentTTP: TemplateWidget = {
  name: 'Incident TTPs',
  widget: JSON.stringify({
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
        } as FilterGroup,
      },
    ],
  }),
};

const widgetIncidentType: TemplateWidget = {
  name: 'Incident Type',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetIncidentType',
    perspective: null,
    dataSelection: [{
      attribute: 'incident_type',
    }],
  }),
};

export const hardcodedTemplateWidgets: TemplateWidget[] = [
  widgetContainerCreationDate,
  widgetContainerDescription,
  widgetContainerLabels,
  widgetContainerMarkings,
  widgetContainerModificationDate,
  widgetContainerName,
  widgetContainerIndicators,
  widgetContainerReferences,
  widgetLocationsList,
  widgetDonut,
  widgetIncidentIOC,
  widgetIncidentPriority,
  widgetIncidentSeverity,
  widgetIncidentTasksActions,
  widgetIncidentTTP,
  widgetIncidentType,
];
