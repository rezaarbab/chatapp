import { handleRequest } from "./router";

interface Env {
  DB: D1Database;
  NOW_OVERRIDE_MS?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
  },
};
