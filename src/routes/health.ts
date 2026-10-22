import { jsonResponse } from '../utils.ts';

export function handleHealth(): Response {
  return jsonResponse(
    {
      ok: true,
      service: 'zeroauth',
    },
    { status: 200 },
  );
}
