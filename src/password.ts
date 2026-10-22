import { sha256Hex } from './utils.ts';

export const MAX_PASSWORD_LENGTH = 1024;

export function constantTimeEqualHex(a: string, b: string): boolean {
  const left = a.toLowerCase();
  const right = b.toLowerCase();
  let diff = left.length ^ right.length;

  for (let index = 0; index < left.length; index += 1) {
    diff |= left.charCodeAt(index) ^ (right.charCodeAt(index) ?? 0);
  }

  return diff === 0;
}

export async function verifyPassword(input: string, expectedDigest: string): Promise<boolean> {
  if (input.length > MAX_PASSWORD_LENGTH) {
    return false;
  }

  const digest = await sha256Hex(input);
  return constantTimeEqualHex(digest, expectedDigest);
}
