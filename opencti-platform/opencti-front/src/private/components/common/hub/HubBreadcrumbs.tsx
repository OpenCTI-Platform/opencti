import React from 'react';
import { Text } from '@filigran/design-system';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';

interface HubBreadcrumbsProps {
  /** The English source label of the hub, the current entry of the breadcrumb. */
  hub: string;
  /** The English source labels of the breadcrumb entries above the hub, if any. */
  parents?: string[];
}

/**
 * The breadcrumb of the pages a hub draws itself (first use, no access).
 *
 * The separator sets the height of a breadcrumb row and the library draws none for a single entry,
 * whose row is then shorter: an invisible separator keeps it at the height of a row with a parent,
 * so the first block of the page starts at the offset of the core pages.
 */
const HubBreadcrumbs = ({ hub, parents = [] }: HubBreadcrumbsProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Breadcrumbs
      elements={[...parents.map((label) => ({ label: t_i18n(label) })), { label: t_i18n(hub), current: true }]}
      adornment={parents.length === 0 ? (
        <span aria-hidden="true" className="invisible" data-testid="hub-breadcrumb-separator">
          <Text as="span" variant="content-base">/</Text>
        </span>
      ) : undefined}
    />
  );
};

export default HubBreadcrumbs;
