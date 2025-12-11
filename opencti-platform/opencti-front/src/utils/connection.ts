type Connection<T> = {
  readonly edges: ReadonlyArray<{
    readonly node: T;
  } | null | undefined> | null | undefined;
} | null | undefined;

// eslint-disable-next-line import/prefer-default-export
export function getNodes<T>(data?: Connection<T>) {
  return (data?.edges ?? []).flatMap((e) => {
    if (!e?.node) return [];
    return e.node;
  });
}
