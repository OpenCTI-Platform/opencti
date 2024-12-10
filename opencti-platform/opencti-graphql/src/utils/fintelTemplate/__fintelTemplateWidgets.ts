import { v4 as uuidv4 } from 'uuid';
import { type FintelTemplateWidget, WidgetPerspective } from '../../generated/graphql';

// hardcoded widgets

export const containerColumns = [
  { label: 'Creation date', attribute: 'created_at', displayStyle: 'text', variableName: 'containerCreationDate' },
  { label: 'Description', attribute: 'description', variableName: 'containerDescription' },
  { label: 'Labels', attribute: 'objectLabel.value', variableName: 'containerLabels' },
  { label: 'Markings', attribute: 'objectMarking.definition', variableName: 'containerMarkings' },
  { label: 'Modification date', attribute: 'updated_at', variableName: 'containerModificationDate' },
  { label: 'Name', attribute: 'name', variableName: 'containerName' },
  { label: 'Author', attribute: 'createdBy.name', variableName: 'containerAuthor' },
  { label: 'Confidence level', attribute: 'confidence', variableName: 'containerConfidenceLevel' },
  { label: 'Reliability (of author)', attribute: 'createdBy.x_opencti_reliability', variableName: 'containerReliabilityOfAuthor' },
  { label: 'External references', attribute: 'externalReferences.edges.node.url', displayStyle: 'list', variableName: 'containerReferences' },
];

export const widgetReportMultiAttributes: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'widgetReportMultiAttributesId',
  widget: {
    type: 'attribute',
    id: uuidv4(),
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
  },
};

export const widgetGroupingMultiAttributes: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'widgetGroupingMultiAttributesId',
  widget: {
    type: 'attribute',
    id: uuidv4(),
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
  }
};

export const widgetRFIMultiAttributes: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'widgetRFIMultiAttributesId',
  widget: {
    type: 'attribute',
    id: uuidv4(),
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
  },
};

export const widgetRFTMultiAttributes: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'widgetRFTMultiAttributesId',
  widget: {
    type: 'attribute',
    id: uuidv4(),
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
  },
};

export const widgetIncidentResponseMultiAttributes: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'widgetIncidentResponseMultiAttributesId',
  widget: {
    type: 'attribute',
    id: uuidv4(),
    perspective: null,
    dataSelection: [{
      columns: [
        ...containerColumns,
        { label: 'Priority', attribute: 'priority', variableName: 'incidentPriority' },
        { label: 'Severity', attribute: 'severity', variableName: 'incidentSeverity' },
        { label: 'Incident type', attribute: 'response_types', variableName: 'types' },
      ],
      instance_id: 'SELF_ID',
    }],
    parameters: {
      title: 'widgetIncidentResponseMultiAttributes',
    }
  },
};

export const widgetContainerObservables: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'containerObservablesId',
  widget: {
    type: 'list',
    id: uuidv4(),
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
        ],
      },
    ],
    parameters: {
      title: 'containerObservables',
    }
  },
};

export const widgetLocationsList: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'locationsListId',
  widget: {
    id: uuidv4(),
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
  },
};

export const widgetDonut: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'widgetGraphId',
  widget: {
    id: uuidv4(),
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
  },
};

export const widgetIncidentIOC: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'incidentIOCId',
  widget: {
    type: 'list',
    id: uuidv4(),
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
  },
};

export const widgetIndicators: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'indicatorsId',
  widget: {
    type: 'list',
    id: uuidv4(),
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
        ],
      },
    ],
    parameters: {
      title: 'indicators',
    }
  },
};

export const widgetIncidentTasksActions: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'incidentTasksAndActionsId',
  widget: {
    type: 'list',
    id: uuidv4(),
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
          { label: 'Status', attribute: 'status.template.name' },
        ],
      },
    ],
    parameters: {
      title: 'incidentTasksAndActions',
    }
  },
};

export const widgetAttackPatterns: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'attackPatternsId',
  widget: {
    type: 'list',
    id: uuidv4(),
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
          { label: 'Technique ID', attribute: 'x_mitre_id' },
          { label: 'Technique', attribute: 'representative.main' },
        ],
      },
    ],
    parameters: {
      title: 'attackPatterns',
    }
  },
};

export const widgetThreats: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'threatsId',
  widget: {
    type: 'list',
    id: uuidv4(),
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
          { label: 'Alias', attribute: 'aliases' },
        ],
      },
    ],
    parameters: {
      title: 'threats',
    }
  },
};

export const widgetVictims: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'victimsId',
  widget: {
    type: 'list',
    id: uuidv4(),
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
          { label: 'Alias', attribute: 'x_opencti_aliases' },
        ],
      },
    ],
  },
};

export const widgetAllEntitiesAndObservables: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'allEntitiesAndObservablesId',
  widget: {
    type: 'list',
    id: uuidv4(),
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
        ],
      },
    ],
    parameters: {
      title: 'allEntitiesAndObservables',
    }
  },
};
