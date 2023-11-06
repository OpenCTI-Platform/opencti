// as stored in the CSV Mapper and sent to backend
export interface Attribute {
  key: string;
  // it's either column or based_on, not both
  based_on: {
    representations: ReadonlyArray<string | null> | null;
  } | null;
  column: {
    column_name: string | null;
    configuration?: AttributeConfiguration;
  } | null;
}

// enhanced with schema info
export interface AttributeWithMetadata extends Attribute {
  mandatory?: boolean;
  multiple?: boolean | null;
  type?: string;
}

export interface AttributeConfiguration {
  separator?: string;
  pattern_date?: string;
}
