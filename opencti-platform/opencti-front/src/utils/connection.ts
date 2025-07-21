type Connection<T> = {
  readonly edges?: readonly {
    readonly node?: T | null
  }[] | null
} | null;

// eslint-disable-next-line import/prefer-default-export
export function getNodes<T>(data?: Connection<T>) {
  return (data?.edges ?? []).flatMap((e) => {
    if (!e.node) return [];
    return e.node;
  });
}
