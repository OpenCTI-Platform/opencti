import React, { type ComponentType } from 'react';
import EntityDiffTab from '@components/common/time_machine/EntityDiffTab';
import EntityAsOfSection from '@components/common/time_machine/EntityAsOfSection';
import { CHANGES_SECTION_AS_OF, CHANGES_SECTION_COMPARE, carriesAsOfDate } from '@components/common/time_machine/timeMachineUtils';

/** Search parameter of the Changes tab holding the open section, so that each section can be linked to. */
export { CHANGES_SECTION_SEARCH_PARAM } from '@components/common/time_machine/timeMachineUtils';

export interface EntityChangesSectionProps {
  entityId: string;
  basePath: string;
}

export interface EntityChangesSection {
  /** Value of the section switch, also the `section` search parameter of the tab. */
  key: string;
  /** English source string, translated by the tab. */
  label: string;
  Component: ComponentType<EntityChangesSectionProps>;
  /** For a link that names no section: whether its other parameters belong to this section (a date opens the as-of view). */
  matchesLink?: (searchParams: URLSearchParams) => boolean;
}

const CompareDatesSection = ({ entityId }: EntityChangesSectionProps) => <EntityDiffTab entityId={entityId} />;

/**
 * The sections of an entity's Changes tab, in display order (information architecture directive,
 * OpenCTI-Platform/opencti#18685): compare the entity between two dates, view it as it was at a past date, then the
 * other views of how it changed. There is no separate "Diff" or "Merge history" tab: a feature showing how an entity
 * changed registers its section here, following .github/instructions/frontend/patterns/changes-tab-sections.md.
 */
export const ENTITY_CHANGES_SECTIONS: EntityChangesSection[] = [
  { key: CHANGES_SECTION_COMPARE, label: 'Compare dates', Component: CompareDatesSection },
  { key: CHANGES_SECTION_AS_OF, label: 'View as of', Component: EntityAsOfSection, matchesLink: carriesAsOfDate },
];
