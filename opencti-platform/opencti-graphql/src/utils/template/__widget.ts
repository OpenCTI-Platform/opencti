import { type TemplateWidget, WidgetPerspective } from '../../generated/graphql';

// hardcoded widgets

const containerColumns = [
  { label: 'Creation date', attribute: 'created_at', displayStyle: 'text', variableName: 'containerCreationDate' },
  { label: 'Description', attribute: 'description', variableName: 'containerDescription' },
  { label: 'Labels', attribute: 'objectLabel.value', variableName: 'containerLabels' },
  { label: 'Markings', attribute: 'objectMarking.definition', variableName: 'containerMarkings' },
  { label: 'Modification date', attribute: 'modified', variableName: 'containerModificationDate' },
  { label: 'Name', attribute: 'name', variableName: 'containerName' },
  { label: 'Author', attribute: 'createdBy.name', variableName: 'containerAuthor' },
  { label: 'Reliability', attribute: 'reliability', variableName: 'containerReliability' },
  { label: 'Confidence level', attribute: 'confidence', variableName: 'containerConfidenceLevel' },
  { label: 'External references', attribute: 'externalReferences.edges.node.url', displayStyle: 'list', variableName: 'containerReferences' },
];

const widgetReportMultiAttributes: TemplateWidget = {
  name: 'widgetReportMultiAttributes',
  id: 'widgetReportMultiAttributesId',
  description: 'This is a multi attributes widget.',
  widget: {
    type: 'attribute',
    id: 'widgetMultiAttributes',
    perspective: null,
    dataSelection: [{
      columns: [
        ...containerColumns,
        { label: 'Publication date', attribute: 'published', variableName: 'reportPublicationDate' },
        { label: 'Report types', attribute: 'report_types', variableName: 'types' },
      ],
      instance_id: 'SELF_ID',
    }],
  },
};

const widgetGroupingMultiAttributes: TemplateWidget = {
  name: 'widgetGroupingMultiAttributes',
  id: 'widgetGroupingMultiAttributesId',
  description: 'This is a multi attributes widget.',
  widget: {
    type: 'attribute',
    id: 'widgetMultiAttributes',
    perspective: null,
    dataSelection: [{
      columns: [
        ...containerColumns,
        { label: 'Grouping types', attribute: 'context', variableName: 'context' },
      ],
      instance_id: 'SELF_ID',
    }],
  },
};

const widgetRFIMultiAttributes: TemplateWidget = {
  name: 'widgetRFIMultiAttributes',
  id: 'widgetRFIMultiAttributesId',
  description: 'This is a multi attributes widget.',
  widget: {
    type: 'attribute',
    id: 'widgetMultiAttributes',
    perspective: null,
    dataSelection: [{
      columns: [
        ...containerColumns,
        { label: 'Information types', attribute: 'information_types', variableName: 'types' },
      ],
      instance_id: 'SELF_ID',
    }],
  },
};

const widgetRFTMultiAttributes: TemplateWidget = {
  name: 'widgetRFTMultiAttributes',
  id: 'widgetRFTMultiAttributesId',
  description: 'This is a multi attributes widget.',
  widget: {
    type: 'attribute',
    id: 'widgetMultiAttributes',
    perspective: null,
    dataSelection: [{
      columns: [
        ...containerColumns,
        { label: 'Takedown types', attribute: 'takedown_types', variableName: 'types' },
      ],
      instance_id: 'SELF_ID',
    }],
  },
};

const widgetIncidentResponseMultiAttributes: TemplateWidget = {
  name: 'widgetIncidentResponseMultiAttributes',
  id: 'widgetIncidentResponseMultiAttributesId',
  widget: {
    type: 'attribute',
    id: 'widgetMultiAttributes',
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
  },
};

const widgetContainerObservables: TemplateWidget = {
  name: 'containerObservables',
  id: 'containerObservablesId',
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
  id: 'locationsListId',
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
  id: 'widgetGraphId',
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
  id: 'incidentIOCId',
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

const widgetIndicators: TemplateWidget = {
  name: 'indicators',
  id: 'indicatorsId',
  widget: {
    type: 'list',
    id: 'widgetIndicators',
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
  },
};

const widgetIncidentTasksActions: TemplateWidget = {
  name: 'incidentTasksAndActions',
  id: 'incidentTasksAndActionsId',
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

const widgetAttackPatterns: TemplateWidget = {
  name: 'attackPatterns',
  id: 'attackPatternsId',
  widget: {
    type: 'list',
    id: 'widgetAttackPatterns',
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

const widgetThreats: TemplateWidget = {
  name: 'threats',
  id: 'threatsId',
  widget: {
    type: 'list',
    id: 'widgetThreats',
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
  },
};

const widgetVictims: TemplateWidget = {
  name: 'victims',
  id: 'victimsId',
  widget: {
    type: 'list',
    id: 'widgetVictims',
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
  },
};

const widgetAllEntitiesAndObservables: TemplateWidget = {
  name: 'allEntitiesAndObservables',
  id: 'allEntitiesAndObservablesId',
  widget: {
    type: 'list',
    id: 'widgetAllEntitiesAndObservables',
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
  },
};

export const hardcodedTemplateWidgets: TemplateWidget[] = [
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
