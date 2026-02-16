import { describe, expect, it } from 'vitest';
import { resolvePath } from '../../../../src/modules/authenticationProvider/mappings-utils';

describe('mappings-utils', () => {
  describe('resolvePath', () => {
    it('should resolve simple property', async () => {
      const obj = { foo: 'bar' };
      const result = await resolvePath(obj, ['foo']);
      expect(result).toBe('bar');
    });

    it('should resolve nested property', async () => {
      const obj = { foo: { bar: 'baz' } };
      const result = await resolvePath(obj, ['foo', 'bar']);
      expect(result).toBe('baz');
    });

    it('should resolve function returning value', async () => {
      const obj = { foo: () => 'bar' };
      const result = await resolvePath(obj, ['foo']);
      expect(result).toBe('bar');
    });

    it('should resolve nested function returning value', async () => {
      const obj = { foo: { bar: () => 'baz' } };
      const result = await resolvePath(obj, ['foo', 'bar']);
      expect(result).toBe('baz');
    });

    it('should resolve async function returning value', async () => {
      const obj = { foo: async () => 'bar' };
      const result = await resolvePath(obj, ['foo']);
      expect(result).toBe('bar');
    });

    it('should resolve function with arguments', async () => {
      const obj = { foo: (arg: string) => `bar-${arg}` };
      const result = await resolvePath(obj, ['foo', 'suffix']);
      expect(result).toBe('bar-suffix');
    });

    it('should resolve nested function with arguments', async () => {
      // Logic: obj.foo('arg1').bar
      const obj = {
        foo: (arg: string) => ({
          bar: `baz-${arg}`,
        }),
      };
      // For resolvePath, if function has args, it takes next item in array as arg
      // So ['foo', 'arg1', 'bar'] -> obj.foo('arg1').bar
      const result = await resolvePath(obj, ['foo', 'arg1', 'bar']);
      expect(result).toBe('baz-arg1');
    });

    it('should handle missing property gracefully', async () => {
      const obj = { foo: 'bar' };
      const result = await resolvePath(obj, ['baz']);
      expect(result).toBeUndefined();
    });

    it('should handle null/undefined intermediate value', async () => {
      const obj = { foo: null };
      const result = await resolvePath(obj, ['foo', 'bar']);
      expect(result).toBeUndefined();
    });

    it('should handle complex mixed path', async () => {
      const obj = {
        a: {
          b: async (arg: string) => ({
            c: `value-${arg}`,
          }),
        },
      };
      // path: a -> b('arg1') -> c
      const result = await resolvePath(obj, ['a', 'b', 'arg1', 'c']);
      expect(result).toBe('value-arg1');
    });

    it('should resolve function with argument but no provided argument (undefined)', async () => {
      const obj = { foo: (arg: string | undefined) => `bar-${arg}` };
      const result = await resolvePath(obj, ['foo']);
      expect(result).toBe('bar-undefined');
    });
  });
});

