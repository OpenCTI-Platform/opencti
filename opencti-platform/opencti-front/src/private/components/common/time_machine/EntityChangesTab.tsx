import React, { ComponentType } from 'react';
import { useSearchParams } from 'react-router';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import EntityDiffTab from './EntityDiffTab';
import EntityAsOfSection from './EntityAsOfSection';
import { AS_OF_SEARCH_PARAM, CHANGES_SECTION_AS_OF, CHANGES_SECTION_COMPARE, CHANGES_SECTION_SEARCH_PARAM, resolveChangesSection } from './timeMachineUtils';

export interface EntityChangesSectionProps {
  entityId: string;
  basePath: string;
}

export interface EntityChangesSection {
  key: string;
  // i18n key of the section label
  label: string;
  Component: ComponentType<EntityChangesSectionProps>;
}

const CompareDatesSection = ({ entityId }: EntityChangesSectionProps) => <EntityDiffTab entityId={entityId} />;

/**
 * Sections of the Changes tab, in display order. Every section follows the same anatomy: a toolbar row (scope
 * controls on the left, actions on the right), a one-line summary with counts, the table or list of the changes,
 * and an empty state that offers its action, without a section-level breadcrumb.
 * See .github/instructions/frontend/patterns/changes-tab-sections.md.
 */
export const ENTITY_CHANGES_SECTIONS: EntityChangesSection[] = [
  { key: CHANGES_SECTION_COMPARE, label: 'Compare dates', Component: CompareDatesSection },
  { key: CHANGES_SECTION_AS_OF, label: 'View as of', Component: EntityAsOfSection },
];

/**
 * Changes tab of an entity, its single time tab: compare the entity between two dates,
 * view it as it was at a past date, and the other sections listed in ENTITY_CHANGES_SECTIONS.
 * The section is kept in the URL so each view can be shared.
 */
const EntityChangesTab = ({ entityId, basePath }: EntityChangesSectionProps) => {
  const { t_i18n } = useFormatter();
  const [searchParams, setSearchParams] = useSearchParams();
  const current = resolveChangesSection(
    ENTITY_CHANGES_SECTIONS.map(({ key }) => key),
    searchParams.get(CHANGES_SECTION_SEARCH_PARAM),
    searchParams.get(AS_OF_SEARCH_PARAM),
  );
  const handleChange = (section: string) => {
    setSearchParams((params) => {
      const next = new URLSearchParams(params);
      next.set(CHANGES_SECTION_SEARCH_PARAM, section);
      return next;
    }, { replace: true });
  };
  return (
    <Tabs value={current} onValueChange={handleChange} data-testid="time-machine-changes">
      <TabsList aria-label={t_i18n('Changes')} className="mb-4">
        {ENTITY_CHANGES_SECTIONS.map(({ key, label }) => (
          <TabsTrigger key={key} value={key}>{t_i18n(label)}</TabsTrigger>
        ))}
      </TabsList>
      {ENTITY_CHANGES_SECTIONS.map(({ key, Component }) => (
        <TabsContent key={key} value={key}>
          <Component entityId={entityId} basePath={basePath} />
        </TabsContent>
      ))}
    </Tabs>
  );
};

export default EntityChangesTab;
