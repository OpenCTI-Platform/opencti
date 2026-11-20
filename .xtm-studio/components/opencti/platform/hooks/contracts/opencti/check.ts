// The check of the contract opencti of the OpenCTI platform: the token the enrollment made signs in
// as its service account. Runs as enroll.ts does, given what it was given and what it answered.
// Exits 0 when all is there, 1 when something is missing, saying what on its standard error; any
// other code says it could not tell.

interface Input {
  enrollment: { service_account?: { name?: string } };
  output: { token?: string };
}

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
const input = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Input;

const name = input.enrollment.service_account?.name;
if (name) {
  if (!input.output.token) {
    console.error('no token in the enrollment');
    process.exit(1);
  }
  let answer: Response;
  try {
    answer = await fetch('http://localhost:8080/graphql', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${input.output.token}` },
      body: JSON.stringify({ query: '{ me { name } }' }),
    });
  } catch (error) {
    console.error(`opencti: ${(error as Error).message}`);
    process.exit(2);
  }
  const body = (await answer.json().catch(() => ({}))) as { data?: { me?: { name: string } }; errors?: { message: string }[] };
  const me = body.data?.me;
  if (!me) {
    console.error(`the token signs in as nobody: ${body.errors?.[0]?.message ?? answer.status}`);
    process.exit(1);
  }
  if (me.name !== name) {
    console.error(`the token signs in as ${me.name}`);
    process.exit(1);
  }
}
