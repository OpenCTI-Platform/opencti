import type { FilterGroup } from '../../generated/graphql';

export interface WidgetConfigImportData extends ConfigImportData {
  configuration?: string; // widget definition in base64.
}

export interface WidgetConfiguration {
  type: string;
  perspective: string;
  dataSelection: [
    {
      label: string;
      attribute: string;
      date_attribute: string;
      perspective: string;
      isTo: boolean;
      filters: FilterGroup;
      dynamicFrom: FilterGroup;
      dynamicTo: FilterGroup;
    },
  ];
  parameters: {
    title: string;
  };
  layout: {
    w: number;
    h: number;
    x: number;
    y: number;
    i: string;
    moved: boolean;
    static: boolean;
  };
}

export interface ConfigImportData {
  type: string;
  openCTI_version: string;
}
