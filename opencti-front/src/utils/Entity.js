export const resolveLink = (type) => {
  switch (type) {
    case 'organization':
      return '/dashboard/';
    case 'uses':
      return { fromRole: 'user', toRole: 'usage' };
    case 'attributed-to':
      return { fromRole: 'attribution', toRole: 'origin' };
    case 'variant-of':
      return { fromRole: 'variation', toRole: 'original' };
    case 'gathering':
      return { fromRole: 'part_of', toRole: 'gather' };
    case 'related-to':
      return { fromRole: 'relate_from', toRole: 'relate_to' };
    case 'localization':
      return { fromRole: 'localized', toRole: 'location' };
    default:
      return { fromRole: '', toRole: '' };
  }
};

export default resolveRoles;
