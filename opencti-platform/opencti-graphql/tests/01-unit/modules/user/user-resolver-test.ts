import { describe, expect, it } from 'vitest';
import userResolvers from '../../../../src/modules/user/user-resolver';
import { ENTITY_TYPE_USER } from '../../../../src/modules/user/user-types';
import { ENTITY_TYPE_GROUP } from '../../../../src/schema/internalObject';

type FieldResolver<R> = (parent: unknown, args: unknown, context: unknown, info: unknown) => R;

const resolveField = <R>(resolver: unknown, parent: unknown, context: unknown = {}): R => {
  return (resolver as FieldResolver<R>)(parent, {}, context, {});
};

const meUserResolvers = userResolvers.MeUser as Record<string, unknown>;
const memberResolvers = userResolvers.Member as Record<string, unknown>;
const sourceObjectResolvers = userResolvers.EffectiveConfidenceLevelSourceObject as Record<string, unknown>;

describe('User resolvers', () => {
  describe('MeUser preferences defaults', () => {
    it('should fall back on defaults when preferences are not set', () => {
      expect(resolveField(meUserResolvers.language, {})).toEqual('auto');
      expect(resolveField(meUserResolvers.unit_system, {})).toEqual('auto');
      expect(resolveField(meUserResolvers.submenu_show_icons, {})).toEqual(false);
      expect(resolveField(meUserResolvers.submenu_auto_collapse, {})).toEqual(true);
      expect(resolveField(meUserResolvers.monochrome_labels, {})).toEqual(false);
      expect(resolveField(meUserResolvers.unsubscribed_news_feed_types, {})).toEqual([]);
    });

    it('should expose the stored preferences when they are set', () => {
      expect(resolveField(meUserResolvers.language, { language: 'fr-fr' })).toEqual('fr-fr');
      expect(resolveField(meUserResolvers.unit_system, { unit_system: 'Metric' })).toEqual('Metric');
      expect(resolveField(meUserResolvers.submenu_show_icons, { submenu_show_icons: true })).toEqual(true);
      expect(resolveField(meUserResolvers.submenu_auto_collapse, { submenu_auto_collapse: false })).toEqual(false);
      expect(resolveField(meUserResolvers.monochrome_labels, { monochrome_labels: true })).toEqual(true);
      expect(resolveField(meUserResolvers.unsubscribed_news_feed_types, { unsubscribed_news_feed_types: ['alert'] })).toEqual(['alert']);
    });
  });

  describe('Member', () => {
    it('should expose the name of a member that is not a user', () => {
      const group = { id: 'group-id', name: 'Group name', entity_type: ENTITY_TYPE_GROUP };
      expect(resolveField(memberResolvers.name, group, { user: { id: 'other-id' } })).toEqual('Group name');
    });

    it('should expose the name of a user looking at themselves', () => {
      const self = { id: 'user-id', name: 'John Doe', entity_type: ENTITY_TYPE_USER };
      expect(resolveField(memberResolvers.name, self, { user: { id: 'user-id' } })).toEqual('John Doe');
    });

    it('should not resolve a confidence level for a member that is not a user', () => {
      const group = { id: 'group-id', name: 'Group name', entity_type: ENTITY_TYPE_GROUP };
      expect(resolveField(memberResolvers.effective_confidence_level, group)).toBeNull();
    });
  });

  describe('EffectiveConfidenceLevelSourceObject', () => {
    it('should resolve the type from the entity type', () => {
      const resolveType = sourceObjectResolvers.__resolveType as (obj: unknown) => string;
      expect(resolveType({ entity_type: ENTITY_TYPE_USER })).toEqual('User');
      expect(resolveType({ entity_type: ENTITY_TYPE_GROUP })).toEqual('Group');
    });

    it('should fall back to Unknown without an entity type', () => {
      const resolveType = sourceObjectResolvers.__resolveType as (obj: unknown) => string;
      expect(resolveType({})).toEqual('Unknown');
    });
  });
});
