const HASH_KEY = 'type';

/** The type a #type=… URL hash points at, so a link to a type can be shared. */
export const typeFromHash = () => new URLSearchParams(window.location.hash.slice(1)).get(HASH_KEY);

export const typeHash = (typeId: string) => `#${HASH_KEY}=${encodeURIComponent(typeId)}`;
