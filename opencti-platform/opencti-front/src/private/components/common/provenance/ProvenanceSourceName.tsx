import React from 'react';
import { Link } from 'react-router';
import { type ProvenanceSourceRef, resolveProvenanceSourceLink } from './provenanceSourceLinks';

/**
 * Name of a provenance source, linked to the page describing it when a resolver of `provenanceSourceLinks` has one.
 */
const ProvenanceSourceName = ({ source }: { source: ProvenanceSourceRef }) => {
  const link = resolveProvenanceSourceLink(source);
  return link ? <Link to={link}>{source.source_name}</Link> : <span>{source.source_name}</span>;
};

export default ProvenanceSourceName;
