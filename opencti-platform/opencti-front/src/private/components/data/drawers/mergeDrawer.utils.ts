export interface MergeElement {
  id: string;
  entity_type: string;
  name?: string | null;
  description?: string | null;
  x_opencti_description?: string | null;
  aliases?: (string | null)[] | null;
  x_opencti_aliases?: (string | null)[] | null;
  createdBy?: { name: string } | null;
  objectMarking?: { id: string; definition?: string | null; x_opencti_color?: string | null }[] | null;
}

export interface MergePreview {
  keptElement: MergeElement | undefined;
  mergedElements: MergeElement[];
  newAliases: string[];
}

// The kept element is the chosen one, or the first selected element by default.
// The names and aliases of every selected element become the aliases of the kept one.
export const computeMergePreview = (elements: MergeElement[], keptEntityId: string | null): MergePreview => {
  const keptElement = keptEntityId
    ? elements.find((element) => element.id === keptEntityId)
    : elements[0];
  if (!keptElement) {
    return { keptElement, mergedElements: [], newAliases: [] };
  }
  const mergedElements = elements.filter((element) => element.id !== keptElement.id);
  const names = elements
    .map((element) => element.name)
    .filter((name) => name !== keptElement.name);
  const aliases = elements
    .map((element) => (keptElement.aliases !== null ? element.aliases : element.x_opencti_aliases))
    .flat()
    .filter((alias) => alias !== null && alias !== undefined);
  const newAliases = names.concat(aliases)
    .filter((alias): alias is string => !!alias && alias.length > 0);
  return { keptElement, mergedElements, newAliases };
};
