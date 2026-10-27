/*
 * Every badge provider of the graphs is registered here, once, when a graph first loads.
 * A feature adding a badge registers its provider in a file of its own and calls its
 * registration below; the contract is in `graphBadgeRegistry.ts`.
 */
import { registerBuiltinGraphBadges } from './builtinGraphBadges';

registerBuiltinGraphBadges();

export * from './graphBadgeRegistry';
export * from './graphNodeActionRegistry';
