import { type Widget, WidgetPerspective } from '../../generated/graphql';

// hardcoded widgets

const containerColumns = [
  { label: 'Creation date', attribute: 'created_at', displayStyle: 'text', variableName: 'containerCreationDate' },
  { label: 'Description', attribute: 'description', variableName: 'containerDescription' },
  { label: 'Labels', attribute: 'objectLabel.value', variableName: 'containerLabels' },
  { label: 'Markings', attribute: 'objectMarking.definition', variableName: 'containerMarkings' },
  { label: 'Modification date', attribute: 'modified', variableName: 'containerModificationDate' },
  { label: 'Name', attribute: 'name', variableName: 'containerName' },
  { label: 'Author', attribute: 'createdBy.name', variableName: 'containerAuthor' },
  { label: 'Confidence level', attribute: 'confidence', variableName: 'containerConfidenceLevel' },
  { label: 'Reliability (of author)', attribute: 'createdBy.x_opencti_reliability', variableName: 'containerReliabilityOfAuthor' },
  { label: 'External references', attribute: 'externalReferences.edges.node.url', displayStyle: 'list', variableName: 'containerReferences' },
];

const widgetReportMultiAttributes: Widget = {
  type: 'attribute',
  id: 'widgetReportMultiAttributesId',
  perspective: null,
  dataSelection: [{
    columns: [
      ...containerColumns,
      { label: 'Publication date', attribute: 'published', variableName: 'reportPublicationDate' },
      { label: 'Reliability (self)', attribute: 'x_opencti_reliability', variableName: 'reportReliability' },
      { label: 'Report types', attribute: 'report_types', variableName: 'types' },
    ],
    instance_id: 'SELF_ID',
  }],
  parameters: {
    title: 'widgetReportMultiAttributes',
    description: 'This is a multi attributes widget.',
  }
};

const widgetGroupingMultiAttributes: Widget = {
  type: 'attribute',
  id: 'widgetGroupingMultiAttributesId',
  perspective: null,
  dataSelection: [{
    columns: [
      ...containerColumns,
      { label: 'Grouping types', attribute: 'context', variableName: 'context' },
    ],
    instance_id: 'SELF_ID',
  }],
  parameters: {
    title: 'widgetGroupingMultiAttributes',
    description: 'This is a multi attributes widget.',
  }
};

const widgetRFIMultiAttributes: Widget = {
  type: 'attribute',
  id: 'widgetRFIMultiAttributesId',
  perspective: null,
  dataSelection: [{
    columns: [
      ...containerColumns,
      { label: 'Information types', attribute: 'information_types', variableName: 'types' },
    ],
    instance_id: 'SELF_ID',
  }],
  parameters: {
    title: 'widgetRFIMultiAttributes',
    description: 'This is a multi attributes widget.',
  }
};

const widgetRFTMultiAttributes: Widget = {
  type: 'attribute',
  id: 'widgetRFTMultiAttributesId',
  perspective: null,
  dataSelection: [{
    columns: [
      ...containerColumns,
      { label: 'Takedown types', attribute: 'takedown_types', variableName: 'types' },
    ],
    instance_id: 'SELF_ID',
  }],
  parameters: {
    title: 'widgetRFTMultiAttributes',
    description: 'This is a multi attributes widget.',
  }
};

const widgetIncidentResponseMultiAttributes: Widget = {
  type: 'attribute',
  id: 'widgetIncidentResponseMultiAttributesId',
  perspective: null,
  dataSelection: [{
    columns: [
      ...containerColumns,
      { label: 'Priority', attribute: 'priority', variableName: 'incidentPriority' },
      { label: 'Severity', attribute: 'severity', variableName: 'incidentSeverity' },
      { label: 'Incident type', attribute: 'response_types', variableName: 'incidentType' },
    ],
    instance_id: 'SELF_ID',
  }],
  parameters: {
    title: 'widgetIncidentResponseMultiAttributes',
  }
};

const widgetContainerObservables: Widget = {
  type: 'list',
  id: 'containerObservablesId',
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
  parameters: {
    title: 'containerObservables',
  }
};

const widgetLocationsList: Widget = {
  id: 'locationsListId',
  type: 'list',
  perspective: WidgetPerspective.Entities,
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
  parameters: {
    title: 'Locations contained in the report',
    description: 'List of the locations contained in a container',
  }
};

const widgetDonut: Widget = {
  id: 'widgetGraphId',
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
    title: 'widgetGraph',
  },
};

const widgetIncidentIOC: Widget = {
  type: 'list',
  id: 'incidentIOCId',
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
  parameters: {
    title: 'incidentIOC',
  }
};

const widgetIndicators: Widget = {
  type: 'list',
  id: 'indicatorsId',
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
        { label: 'Indicator types', attribute: 'indicator_types' },
        { label: 'Indicator pattern', attribute: 'pattern' },
        { label: 'Description', attribute: 'description' },
      ],
    },
  ],
  parameters: {
    title: 'indicators',
  }
};

const widgetIncidentTasksActions: Widget = {
  type: 'list',
  id: 'incidentTasksAndActionsId',
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
  parameters: {
    title: 'incidentTasksAndActions',
  }
};

const widgetAttackPatterns: Widget = {
  type: 'list',
  id: 'attackPatternsId',
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
  parameters: {
    title: 'attackPatterns',
  }
};

const widgetThreats: Widget = {
  type: 'list',
  id: 'threatsId',
  perspective: WidgetPerspective.Entities,
  dataSelection: [
    {
      perspective: WidgetPerspective.Entities,
      filters: JSON.stringify({
        mode: 'and',
        filters: [
          { key: ['entity_type'], values: ['Threat-Actor-Group', 'Threat-Actor-Individual', 'Intrusion-Set'] },
          { key: ['objects'], values: ['SELF_ID'] },
        ],
        filterGroups: [],
      }),
      columns: [
        { label: 'Type', attribute: 'entity_type' },
        { label: 'Name', attribute: 'name' },
        { label: 'Alias', attribute: 'alias' },
      ],
    },
  ],
  parameters: {
    title: 'threats',
  }
};

const widgetVictims: Widget = {
  type: 'list',
  id: 'victimsId',
  perspective: WidgetPerspective.Entities,
  dataSelection: [
    {
      perspective: WidgetPerspective.Entities,
      filters: JSON.stringify({
        mode: 'and',
        filters: [
          { key: ['entity_type'], values: ['Sector', 'Individual', 'Organization'] },
          { key: ['objects'], values: ['SELF_ID'] },
        ],
        filterGroups: [],
      }),
      columns: [
        { label: 'Type', attribute: 'entity_type' },
        { label: 'Name', attribute: 'name' },
        { label: 'Alias', attribute: 'alias' },
      ],
    },
  ],
};

const widgetAllEntitiesAndObservables: Widget = {
  type: 'list',
  id: 'allEntitiesAndObservablesId',
  perspective: WidgetPerspective.Entities,
  dataSelection: [
    {
      perspective: WidgetPerspective.Entities,
      filters: JSON.stringify({
        mode: 'and',
        filters: [
          { key: ['entity_type'], values: ['Stix-Core-Object', 'Stix-Cyber-Observable'] },
          { key: ['objects'], values: ['SELF_ID'] },
        ],
        filterGroups: [],
      }),
      columns: [
        { label: 'Type', attribute: 'entity_type' },
        { label: 'Representative', attribute: 'representative.main' },
        { label: 'Description', attribute: 'description' },
      ],
    },
  ],
  parameters: {
    title: 'allEntitiesAndObservables',
  }
};

export const hardcodedTemplateWidgets: Widget[] = [
  widgetReportMultiAttributes,
  widgetIncidentResponseMultiAttributes,
  widgetGroupingMultiAttributes,
  widgetRFIMultiAttributes,
  widgetRFTMultiAttributes,
  widgetContainerObservables,
  widgetLocationsList,
  widgetDonut,
  widgetIncidentIOC,
  widgetIndicators,
  widgetIncidentTasksActions,
  widgetAttackPatterns,
  widgetThreats,
  widgetVictims,
  widgetAllEntitiesAndObservables,
];
