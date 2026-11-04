interface SelectedInvestigationEntity {
  id: string;
}

interface InvestigationSelectionEligibility {
  numberOfSelectedElements: number;
  selectAll: boolean;
  selectedTypes: string[];
  stixCyberObservableTypes: string[];
  stixCoreRelationshipTypes: string[];
  stixDomainObjectTypes: string[];
  isInDraft?: boolean;
}

export const buildInvestigationEntityIds = (
  selectedElements: Record<string, SelectedInvestigationEntity>,
  knowledgeEntityId?: string,
) => Array.from(new Set([
  ...Object.values(selectedElements).map(({ id }) => id),
  ...(knowledgeEntityId ? [knowledgeEntityId] : []),
]));

export const isInvestigationSelectionEnabled = ({
  numberOfSelectedElements,
  selectAll,
  selectedTypes,
  stixCyberObservableTypes,
  stixCoreRelationshipTypes,
  stixDomainObjectTypes,
  isInDraft = false,
}: InvestigationSelectionEligibility) => {
  if (isInDraft || selectAll || numberOfSelectedElements === 0) {
    return false;
  }
  const supportedTypes = new Set([
    'Stix-Cyber-Observable',
    'Stix-Domain-Object',
    'stix-core-relationship',
    'stix-sighting-relationship',
    ...stixCyberObservableTypes,
    ...stixCoreRelationshipTypes,
    ...stixDomainObjectTypes,
  ]);
  return selectedTypes.length > 0
    && selectedTypes.every((type) => supportedTypes.has(type));
};
