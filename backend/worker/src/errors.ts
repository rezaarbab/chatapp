export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export function errorResponse(e: unknown): Response {
  if (e instanceof HttpError) {
    return jsonResponse({ error: { code: e.code, message: e.message } }, e.status);
  }
  return jsonResponse({ error: { code: "INTERNAL", message: "internal error" } }, 500);
}
