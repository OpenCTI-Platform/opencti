// The contract opencti of the OpenCTI platform: deletes the service account an enrollment made, its
// tokens with it. Runs as enroll.ts does, given what it was given.

interface Input {
  enrollment: { service_account?: { name?: string } };
}

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
const input = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Input;

const gql = async <T>(query: string, variables: Record<string, unknown> = {}): Promise<T> => {
  const answer = await fetch('http://localhost:8080/graphql', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${process.env['APP__ADMIN__TOKEN']}` },
    body: JSON.stringify({ query, variables }),
  });
  const body = (await answer.json()) as { data: T; errors?: { message: string }[] };
  if (body.errors?.length) {
    console.error(`opencti: ${body.errors[0]!.message}`);
    process.exit(1);
  }
  return body.data;
};

const name = input.enrollment.service_account?.name;
if (name) {
  const users = await gql<{ users: { edges: { node: { id: string; name: string } }[] } }>('query ($search: String) { users(search: $search, first: 100) { edges { node { id name } } } }', { search: name });
  const user = users.users.edges.map(({ node }) => node).find((each) => each.name === name);
  if (user) await gql('mutation ($id: ID!) { userEdit(id: $id) { delete } }', { id: user.id });
}
