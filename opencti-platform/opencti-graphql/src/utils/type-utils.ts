/**
 * Inverse operation of the built-in Readonly<T> utility type:
 * makes all records of an object mutable.
 */
export type Mutable<T> = { -readonly [P in keyof T]: T[P]; };

type AssertEqual<T, TExpected> = [T] extends [TExpected]
  ? [TExpected] extends [T]
      ? T
      : never
  : never;

/**
 * Compile-time type assertion utility checking that a type T
 * is exactly of type TExpected.
 *
 * @example
 * ```
 * type Fruit = 'banana' | 'strawberry' | 'pineapple';
 * const allFruits = ['banana' as const, 'strawberry' as const, 'pineapple' as const];
 * // Checks for exhaustiveness
 * assertType<typeof allFruits[number][], Fruit[]>(allFruits);
 * ```
 */
export const assertType = <T, TExpected>(_x: AssertEqual<T, TExpected>) => {
  // noop
};
