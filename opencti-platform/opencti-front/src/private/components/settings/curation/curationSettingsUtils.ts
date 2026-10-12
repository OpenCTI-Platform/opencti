export interface AdjudicationAgent {
  readonly agent_slug: string;
  readonly agent_name: string;
}

export interface AuthorityAttribute {
  readonly name: string;
  readonly label: string;
}

export interface AdjudicationPrerequisites {
  readonly enterprise_edition: boolean;
  readonly xtm_one_configured: boolean;
}

/** The agents of the select: the bound ones, plus a stored one XTM One no longer lists, so a save never drops it. */
export const adjudicationAgentOptions = (agents: readonly AdjudicationAgent[], storedSlug?: string | null): AdjudicationAgent[] => {
  const options = [...agents];
  if (storedSlug && !options.some((agent) => agent.agent_slug === storedSlug)) {
    options.push({ agent_slug: storedSlug, agent_name: storedSlug });
  }
  return options;
};

/** The attributes a field authority rule can target on the entity type, labelled and sorted, the stored one kept. */
export const authorityAttributeOptions = (
  attributes: readonly AuthorityAttribute[] | undefined,
  current: string,
  translate: (label: string) => string,
): AuthorityAttribute[] => {
  const options = [...(attributes ?? [])];
  if (current && !options.some((attribute) => attribute.name === current)) {
    options.push({ name: current, label: current });
  }
  return options
    .map((attribute) => ({ name: attribute.name, label: translate(attribute.label) }))
    .sort((left, right) => left.label.localeCompare(right.label));
};

/** What adjudication still needs on this platform, the Enterprise Edition first: null when nothing is missing. */
export const missingAdjudicationPrerequisite = (setup: AdjudicationPrerequisites): 'enterprise_edition' | 'xtm_one' | null => {
  if (!setup.enterprise_edition) return 'enterprise_edition';
  if (!setup.xtm_one_configured) return 'xtm_one';
  return null;
};
