import { handleRequest } from './app.ts';
import { AuthStore } from './auth-store.ts';
import type { Env } from './types.ts';

export { AuthStore };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
  },
} satisfies ExportedHandler<Env>;
