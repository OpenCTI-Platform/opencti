import type { BasicStoreEntityFintelTemplate } from '../../../../src/modules/fintelTemplate/fintelTemplate-types';

// The default fintel template of the reports, published, with a widget, next to the attributes that must never be exported.
// The filters of the widget are empty, so that exporting it reads nothing on the platform
export const reportFintelTemplate = {
  id: 'report-fintel-template-id',
  internal_id: 'report-fintel-template-id',
  standard_id: 'finteltemplate--2c5e8f1a-4b3d-5e6f-8a9b-0c1d2e3f4a5b',
  entity_type: 'FintelTemplate',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'Executive Summary',
  description: 'The summary of a report',
  settings_types: ['Report'],
  instance_filters: null,
  template_content: '<p>$containerRepresentative</p>',
  start_date: '2026-01-02T00:00:00.000Z',
  default: true,
  include_cover_page_by_default: true,
  include_back_page_by_default: false,
  fintel_template_widgets: [{
    variable_name: 'widgetSelfAttributes',
    widget: {
      id: 'report-widget-id',
      type: 'attribute',
      perspective: null,
      dataSelection: [{
        instance_id: 'SELF_ID',
        columns: [{ label: 'Representative', attribute: 'representative.main', variableName: 'containerRepresentative' }],
        filters: '{}',
        dynamicFrom: '{}',
        dynamicTo: '{}',
      }],
      parameters: { title: 'Attributes of the instance' },
    },
  }],
} as unknown as BasicStoreEntityFintelTemplate;

// A template of another entity type: not published, without description nor widget, not the default
export const groupingFintelTemplate = {
  ...reportFintelTemplate,
  id: 'grouping-fintel-template-id',
  internal_id: 'grouping-fintel-template-id',
  standard_id: 'finteltemplate--7a8b9c0d-1e2f-5a3b-9c4d-5e6f7a8b9c0d',
  name: 'Incident brief',
  description: undefined,
  settings_types: ['Grouping'],
  template_content: '',
  start_date: null,
  default: false,
  include_back_page_by_default: undefined,
  fintel_template_widgets: [],
} as unknown as BasicStoreEntityFintelTemplate;

export const ALL_FINTEL_TEMPLATES = [reportFintelTemplate, groupingFintelTemplate];
