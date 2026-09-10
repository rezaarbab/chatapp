import type { Env } from "./env";

export default {
  async fetch(_request: Request, _env: Env): Promise<Response> {
    return new Response("chatapp worker", { status: 200 });
  },
};
