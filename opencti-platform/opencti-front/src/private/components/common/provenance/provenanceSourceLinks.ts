export interface ProvenanceSourceRef {
  readonly source_id: string;
  readonly source_kind: string;
  readonly source_name: string;
}

/** In-app path of the page describing a source, or null when the resolver does not handle it. */
export type ProvenanceSourceLinkResolver = (source: ProvenanceSourceRef) => string | null;

const authorEntityLink: ProvenanceSourceLinkResolver = (source) => {
  return source.source_kind === 'author' ? `/dashboard/id/${source.source_id}` : null;
};

/**
 * Pages describing a provenance source, tried in order: the first link wins and a source without link renders as
 * plain text. Source Intelligence registers its scorecard resolver first, so that every source of the Sources card
 * links to its scorecard (information architecture directive, OpenCTI-Platform/opencti#18685).
 */
export const PROVENANCE_SOURCE_LINK_RESOLVERS: ProvenanceSourceLinkResolver[] = [
  authorEntityLink,
];

export const resolveProvenanceSourceLink = (
  source: ProvenanceSourceRef,
  resolvers: ReadonlyArray<ProvenanceSourceLinkResolver> = PROVENANCE_SOURCE_LINK_RESOLVERS,
): string | null => {
  for (let index = 0; index < resolvers.length; index += 1) {
    const link = resolvers[index](source);
    if (link) {
      return link;
    }
  }
  return null;
};
