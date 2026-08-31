import React, { FunctionComponent, ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Breadcrumbs as FdsBreadcrumbs } from '@filigran/design-system';
import DangerZoneChip from '@components/common/danger_zone/DangerZoneChip';
import { useFormatter } from './i18n';

interface element {
  label: string;
  link?: string;
  current?: boolean;
}

interface BreadcrumbsProps {
  elements: element[];
  noMargin?: boolean;
  isSensitive?: boolean;
  /**
   * Content shown beside the path — an information icon and its tooltip, a status marker.
   */
  adornment?: ReactNode;
}

/**
 * The page path, rendered by the design-system Breadcrumbs.
 */
const Breadcrumbs: FunctionComponent<BreadcrumbsProps> = ({ elements, noMargin = false, isSensitive = false, adornment }) => {
  const { t_i18n } = useFormatter();

  // Labels go through WHOLE. The library truncates in CSS and keeps the full
  // string in the DOM and in `title`; pre-cutting them here would ship a double
  // ellipsis and a tooltip repeating the cut text.
  const items = elements.map(({ label, link, current }) => ({
    label,
    ...(current ? { current: true } : {}),
    ...(!current && link ? { to: link } : {}),
  }));

  // The sensitive-zone chip is not a path entry, so it goes in the adornment slot rather than
  // inside the list.
  const beside = isSensitive ? (
    <>
      <DangerZoneChip />
      {adornment}
    </>
  ) : adornment;

  return (
    <FdsBreadcrumbs
      items={items}
      linkComponent={Link}
      adornment={beside}
      label={t_i18n('Breadcrumb')}
      id="page-breadcrumb"
      data-testid="navigation"
      className={noMargin ? undefined : 'mb-2'}
    />
  );
};

export default Breadcrumbs;
