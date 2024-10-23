import type { FilterGroup, TemplateWidget } from '../../generated/graphql';

// hardcoded widgets

const widgetContainerCreationDate: TemplateWidget = {
  name: 'containerCreationDate',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerCreationDate',
    perspective: null,
    dataSelection: [{
      columns: [{ label: 'creationDate', attribute: 'created_at', displayStyle: 'text' }],
    }],
  }),
};

const widgetContainerDescription: TemplateWidget = {
  name: 'containerDescription',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerDescription',
    perspective: null,
    dataSelection: [{
      columns: [{ label: 'Description', attribute: 'description' }],
    }],
  }),
};

const widgetContainerLabels: TemplateWidget = {
  name: 'containerLabels',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerLabels',
    perspective: null,
    dataSelection: [{
      columns: [{ label: 'Labels', attribute: 'objectLabel' }],
    }],
  }),
};

const widgetContainerMarkings: TemplateWidget = {
  name: 'containerMarkings',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerMarkings',
    perspective: null,
    dataSelection: [{
      columns: [{ label: 'Markings', attribute: 'objectMarking' }],
    }],
  }),
};

const widgetContainerModificationDate: TemplateWidget = {
  name: 'containerModificationDate',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerModificationDate',
    perspective: null,
    dataSelection: [{
      columns: [{ label: 'ModificationDate', attribute: 'modified' }],
    }],
  }),
};

const widgetContainerName: TemplateWidget = {
  name: 'containerName',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerName',
    perspective: null,
    dataSelection: [{
      columns: [{ label: 'Name', attribute: 'name' }],
    }],
  }),
};

const widgetContainerIndicators: TemplateWidget = {
  name: 'containerIndicators',
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
        columns: [
          { label: 'Indicator type', attribute: 'indicator_types' },
          { label: 'Indicator', attribute: 'representative.main' },
          { label: 'Description', attribute: 'description' }
        ],
      },
    ],
  }),
};

const widgetContainerObservables: TemplateWidget = {
  name: 'containerObservables',
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
            { key: 'entity_type', values: ['Stix-Cyber-Observable'] },
            { key: 'objects', values: ['CONTAINER_ID'] },
          ],
          filterGroups: [],
        } as FilterGroup,
        columns: [
          { label: 'Observable type', attribute: 'entity_type' },
          { label: 'Value', attribute: 'representative.main' },
          { label: 'Description', attribute: 'description' }
        ],
      },
    ],
  }),
};

const widgetContainerReferences: TemplateWidget = { // TODO : list
  name: 'containerReferences',
  widget: JSON.stringify({
    type: 'attribute',
    id: 'widgetContainerReferences',
    perspective: null,
    dataSelection: [],
  }),
};

const widgetLocationsList: TemplateWidget = {
  name: 'locationsList',
  description: 'List of the locations contained in a container',
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
  name: 'incidentIOC',
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
  name: 'incidentPriority',
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
  name: 'incidentSeverity',
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
  name: 'incidentTasksAndActions',
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
        columns: [
          { label: 'Task', attribute: 'representative.main' },
          { label: 'Due date (UTC)', attribute: 'due_date' },
          { label: 'Status', attribute: 'status' },
        ],
      },
    ],
  }),
};

const widgetIncidentTTP: TemplateWidget = {
  name: 'incidentTTP',
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
            { key: 'entity_type', values: ['Attack-Pattern'] },
            { key: 'objects', values: ['CONTAINER_ID'] },
          ],
          filterGroups: [],
        } as FilterGroup,
        columns: [
          { label: 'Techinque ID', attribute: 'x_mitre_id' },
          { label: 'Technique', attribute: 'representative.main' },
          { label: 'Description', attribute: 'description' },
        ],
      },
    ],
  }),
};

const widgetIncidentType: TemplateWidget = {
  name: 'incidentType',
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
  widgetContainerObservables,
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
