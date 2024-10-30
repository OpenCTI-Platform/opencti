import { type TemplateWidget, WidgetPerspective } from '../../generated/graphql';

// hardcoded widgets

const widgetReportMultiAttributes: TemplateWidget = {
  name: 'widgetReportMultiAttributes',
  widget: {
    type: 'attribute',
    id: 'widgetContainerCreationDate',
    perspective: null,
    dataSelection: [{
      columns: [
        { label: 'creationDate', attribute: 'created_at', displayStyle: 'text', variableName: 'containerCreationDate' },
        { label: 'Description', attribute: 'description', variableName: 'containerDescription' },
        { label: 'Labels', attribute: 'objectLabel.value', variableName: 'containerLabels' },
        { label: 'Markings', attribute: 'objectMarking.definition', variableName: 'containerMarkings' },
        { label: 'ModificationDate', attribute: 'modified', variableName: 'containerModificationDate' },
        { label: 'Name', attribute: 'name', variableName: 'containerName' },
        { label: 'Publication date', attribute: 'published', variableName: 'reportPublicationDate' },
        { label: 'External references', attribute: 'externalReferences.edges.node.url', displayStyle: 'list', variableName: 'containerReferences' },
      ],
      instance_id: 'SELF_ID',
    }],
  },
};

const widgetIncidentResponseMultiAttributes: TemplateWidget = {
  name: 'widgetIncidentResponseMultiAttributes',
  widget: {
    type: 'attribute',
    id: 'widgetContainerCreationDate',
    perspective: null,
    dataSelection: [{
      columns: [
        { label: 'Name', attribute: 'name', variableName: 'containerName' },
        { label: 'creationDate', attribute: 'created_at', displayStyle: 'text', variableName: 'containerCreationDate' },
        { label: 'Description', attribute: 'description', variableName: 'containerDescription' },
        { label: 'Labels', attribute: 'objectLabel.value', variableName: 'containerLabels' },
        { label: 'Markings', attribute: 'objectMarking.definition', variableName: 'containerMarkings' },
        { label: 'ModificationDate', attribute: 'modified', variableName: 'containerModificationDate' },
        { label: 'External references', attribute: 'externalReferences.edges.node.url', displayStyle: 'list', variableName: 'containerReferences' },
        { label: 'Priority', attribute: 'priority', variableName: 'incidentPriority' },
        { label: 'Severity', attribute: 'severity', variableName: 'incidentSeverity' },
        { label: 'Incident type', attribute: 'incident_type', variableName: 'incidentType' },
      ],
      instance_id: 'SELF_ID',
    }],
  },
};

const widgetContainerIndicators: TemplateWidget = {
  name: 'containerIndicators',
  widget: {
    type: 'list',
    id: 'widgetContainerIndicators',
    perspective: WidgetPerspective.Entities,
    dataSelection: [
      {
        perspective: WidgetPerspective.Entities,
        filters: JSON.stringify({
          mode: 'and',
          filters: [
            { key: ['entity_type'], values: ['Indicator'] },
            { key: ['objects'], values: ['SELF_ID'] },
          ],
          filterGroups: [],
        }),
        columns: [
          { label: 'Indicator type', attribute: 'indicator_types' },
          { label: 'Indicator', attribute: 'representative.main' },
          { label: 'Description', attribute: 'description' }
        ],
      },
    ],
  },
};

const widgetContainerObservables: TemplateWidget = {
  name: 'containerObservables', // add an id
  widget: {
    type: 'list',
    id: 'widgetContainerIndicators',
    perspective: WidgetPerspective.Entities,
    dataSelection: [
      {
        perspective: WidgetPerspective.Entities,
        filters: JSON.stringify({
          mode: 'and',
          filters: [
            { key: ['entity_type'], values: ['Stix-Cyber-Observable'] },
            { key: ['objects'], values: ['SELF_ID'] },
          ],
          filterGroups: [],
        }),
        columns: [
          { label: 'Observable type', attribute: 'entity_type' },
          { label: 'Value', attribute: 'representative.main' },
          { label: 'Description', attribute: 'description' }
        ],
      },
    ],
  },
};

const widgetLocationsList: TemplateWidget = {
  name: 'locationsList',
  description: 'List of the locations contained in a container',
  widget: {
    id: 'widgetList_id',
    type: 'list',
    perspective: WidgetPerspective.Entities,
    parameters: {
      title: 'Locations contained in the report',
    },
    dataSelection: [
      {
        perspective: WidgetPerspective.Entities,
        filters: JSON.stringify({
          mode: 'and',
          filters: [
            { key: ['entity_type'], values: ['Country', 'City', 'Region', 'Position', 'Administrative-Area'] },
            { key: ['objects'], values: ['SELF_ID'] },
          ],
          filterGroups: [],
        }),
      },
    ],
  },
};

const widgetDonut: TemplateWidget = {
  name: 'widgetGraph',
  widget: {
    id: 'e1853ae4-f947-4cf6-beca-f2ea6dc564d9',
    type: 'donut',
    perspective: WidgetPerspective.Relationships,
    dataSelection: [
      {
        attribute: 'entity_type',
        date_attribute: 'created_at',
        perspective: WidgetPerspective.Relationships,
        isTo: false,
        number: 100,
      },
    ],
    parameters: {
      title: 'pouet',
    },
  },
};

const widgetIncidentIOC: TemplateWidget = {
  name: 'incidentIOC',
  widget: {
    type: 'list',
    id: 'widgetIncidentIOC',
    perspective: WidgetPerspective.Entities,
    dataSelection: [
      {
        perspective: WidgetPerspective.Entities,
        filters: JSON.stringify({
          mode: 'and',
          filters: [
            { key: ['entity_type'], values: ['Indicator'] },
            { key: ['objects'], values: ['SELF_ID'] },
          ],
          filterGroups: [],
        }),
      },
    ],
  },
};

const widgetIncidentTasksActions: TemplateWidget = {
  name: 'incidentTasksAndActions',
  widget: {
    type: 'list',
    id: 'widgetIncidentTasksActions',
    perspective: WidgetPerspective.Entities,
    dataSelection: [
      {
        perspective: WidgetPerspective.Entities,
        filters: JSON.stringify({
          mode: 'and',
          filters: [
            { key: ['entity_type'], values: ['Task'] },
            { key: ['objects'], values: ['SELF_ID'] },
          ],
          filterGroups: [],
        }),
        columns: [
          { label: 'Task', attribute: 'representative.main' },
          { label: 'Due date (UTC)', attribute: 'due_date' },
          { label: 'Status', attribute: 'status' },
        ],
      },
    ],
  },
};

const widgetIncidentTTP: TemplateWidget = {
  name: 'incidentTTP',
  widget: {
    type: 'list',
    id: 'widgetIncidentTTP',
    perspective: WidgetPerspective.Entities,
    dataSelection: [
      {
        perspective: WidgetPerspective.Entities,
        filters: JSON.stringify({
          mode: 'and',
          filters: [
            { key: ['entity_type'], values: ['Attack-Pattern'] },
            { key: ['objects'], values: ['SELF_ID'] },
          ],
          filterGroups: [],
        }),
        columns: [
          { label: 'Techinque ID', attribute: 'x_mitre_id' },
          { label: 'Technique', attribute: 'representative.main' },
          { label: 'Description', attribute: 'description' },
        ],
      },
    ],
  },
};

export const hardcodedTemplateWidgets: TemplateWidget[] = [
  widgetReportMultiAttributes,
  widgetIncidentResponseMultiAttributes,
  widgetContainerIndicators,
  widgetContainerObservables,
  widgetLocationsList,
  widgetDonut,
  widgetIncidentIOC,
  widgetIncidentTasksActions,
  widgetIncidentTTP,
];
