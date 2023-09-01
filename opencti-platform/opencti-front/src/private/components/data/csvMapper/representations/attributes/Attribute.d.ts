export interface Attribute {
  key: string;
  based_on: {
    representations: ReadonlyArray<string | null> | null;
  } | null;
  column: {
    column_name: string | null;
  } | null;
  mandatory?: boolean;
  multiple?: boolean | null;
  type?: string;
}
