// The overview widget the card follows: the later of Details and Basic information in the page's
// layout, so the card takes the full-width row right under them, above the lists and Notes, which
// stays the last section of every overview. Null when the layout shows neither (the card then
// closes the grid).
export const xtmCardAnchorKey = (layout: ReadonlyArray<{ key: string }>): string | null => {
  let anchor: string | null = null;
  for (const { key } of layout) {
    if (key === 'details' || key === 'basicInformation') anchor = key;
  }
  return anchor;
};

export default xtmCardAnchorKey;
