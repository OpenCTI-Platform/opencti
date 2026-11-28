import { Breadcrumbs, type BreadcrumbsItem } from '@filigran/design-system';
import { typeHash } from '../../shared/typeHash';
import { useNavigationHistory } from './useNavigationHistory';

const MAX_VISIBLE = 5;

export const NavigationBreadcrumb = () => {
  const { crumbs, selectedTypeId } = useNavigationHistory();
  const visible = crumbs.slice(-MAX_VISIBLE);
  const items: BreadcrumbsItem[] = [
    crumbs.length === 0 ? { label: 'Schema', current: true } : { label: 'Schema', href: '#' },
    ...visible.map((crumb, index): BreadcrumbsItem => {
      const current = index === visible.length - 1 && crumb.typeId === selectedTypeId;
      return current ? { label: crumb.label, current: true } : { label: crumb.label, href: typeHash(crumb.typeId) };
    }),
  ];
  return <Breadcrumbs items={items} label="Navigation history" />;
};
