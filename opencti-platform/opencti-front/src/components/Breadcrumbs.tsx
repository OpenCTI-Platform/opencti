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
   * Content shown beside the path — an information icon and its tooltip, a
   * status marker. It lands in the library's `adornment` slot: inside the
   * landmark, OUTSIDE the list, so assistive technology never announces it as
   * a step of the path.
   *
   * Use this instead of wrapping this component in a row of your own. Wrapping
   * is what made the current entry collapse on the trash page: the landmark
   * became a shrink-to-fit flex item, and the width cap it carried then
   * resolved against its own content.
   */
  adornment?: ReactNode;
}

/**
 * The page path, rendered by the design-system Breadcrumbs.
 *
 * This wrapper is the ONLY conversion point: the 163 call sites keep passing
 * `elements` / `noMargin` / `isSensitive` unchanged.
 *
 * Three things it must not lose, each with a consumer in this repository:
 *  - `id="page-breadcrumb"` — dataGrid/components/DataTableBody.tsx keys a table
 *    height on its presence.
 *  - `data-testid="navigation"` — two e2e page models read it, one of them
 *    asserting the visible path equals the labels joined by `/`, which holds
 *    because the library keeps every separator a real text node.
 *  - the bottom margin: `theme.spacing(1)` was 8px, which is `mb-2` on the
 *    library's 4px spacing scale — a bare number in an `sx` is spacing units,
 *    not pixels.
 *
 * `link` maps to `to`, never to `href`: react-router's `Link` spreads rest props
 * before assigning its own `href`, so an `href` passed through it is REPLACED by
 * the current location — a valid, focusable link back to the page the user is
 * already on. The library warns when it detects that; the warning stays silent
 * here because this wrapper passes `to`.
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

  // The sensitive-zone chip is not a path entry, so it goes in the adornment
  // slot rather than inside the list. It used to be rendered as a sibling of
  // the landmark inside a row this wrapper built itself — the slot removes that
  // row, and with it the layout hazard the row created.
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
