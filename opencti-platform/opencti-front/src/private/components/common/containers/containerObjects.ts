/** An object just created by a creation form, as returned by its creation mutation. */
export interface CreatedObject {
  id: string;
  standard_id?: string;
  entity_type: string;
  parent_types?: readonly string[];
  representative?: { main: string } | null;
}
