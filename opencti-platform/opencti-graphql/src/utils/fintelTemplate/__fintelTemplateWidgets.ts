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
  variable_name: 'widgetReportMultiAttributes',
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
  variable_name: 'widgetGroupingMultiAttributes',
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
  variable_name: 'widgetRFIMultiAttributes',
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
  variable_name: 'widgetRFTMultiAttributes',
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
  variable_name: 'widgetIncidentResponseMultiAttributes',
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
  variable_name: 'containerObservables',
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
  },
};

export const widgetIncidentIOC: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'incidentIOC',
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
      title: 'Indicators contained in the container',
    }
  },
};

export const widgetIndicators: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'indicators',
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
      title: 'Indicators contained in the container',
    }
  },
};

export const widgetIncidentTasksActions: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'incidentTasksAndActions',
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
  },
};

export const widgetAttackPatterns: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'attackPatterns',
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
  },
};

export const widgetThreats: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'threats',
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
      title: 'Threats contained in the container',
    }
  },
};

export const widgetVictims: FintelTemplateWidget = {
  id: uuidv4(),
  variable_name: 'victims',
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
  variable_name: 'allEntitiesAndObservables',
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
  },
};
