import { type ComponentType } from 'react';
import EntityMergesSection from '@components/data/curation/EntityMergesSection';

/** Search parameter of the Changes tab holding the open section, so that each section can be linked to. */
export const CHANGES_SECTION_SEARCH_PARAM = 'section';

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
}

/**
 * The sections of an entity's Changes tab, in display order (information architecture directive,
 * OpenCTI-Platform/opencti#18685): the merges the entity took part in, after the compare dates and view as of
 * sections where the platform has them. There is no separate "Diff" or "Merge history" tab: a feature showing how an
 * entity changed registers its section here.
 */
export const ENTITY_CHANGES_SECTIONS: EntityChangesSection[] = [
  { key: 'merges', label: 'Merges', Component: EntityMergesSection },
];
