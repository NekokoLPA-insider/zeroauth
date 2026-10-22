import { exportJWK, generateKeyPair } from 'jose';

const args = process.argv.slice(2);
const pretty = args.includes('--pretty');
const alg = args.find((arg) => !arg.startsWith('--')) ?? 'RS256';
const { privateKey } = await generateKeyPair(alg, { extractable: true });
const privateJwk = await exportJWK(privateKey);

privateJwk.alg = alg;
privateJwk.use = 'sig';

console.log(
  JSON.stringify(
    {
      kid: crypto.randomUUID(),
      privateJwk,
    },
    null,
    pretty ? 2 : 0,
  ),
);
