import {
  desktopApiTarget,
  desktopProxyConfiguration,
  desktopRequestAllowed,
  forwardedRequestHeaders,
  forwardedResponseHeaders,
} from "@/lib/desktop-proxy";

export const dynamic = "force-dynamic";

type RouteContext = { params: Promise<{ path: string[] }> };

async function forward(request: Request, context: RouteContext) {
  const configuration = await desktopProxyConfiguration();
  if (!configuration) {
    return Response.json(
      {
        error: {
          code: "NOT_FOUND",
          message: "Not found",
          details: {},
          request_id: "",
        },
      },
      { status: 404 },
    );
  }
  if (!desktopRequestAllowed(request, configuration.webOrigin)) {
    return Response.json(
      {
        error: {
          code: "DESKTOP_ORIGIN_REJECTED",
          message: "Request origin is not allowed",
          details: {},
          request_id: "",
        },
      },
      { status: 403 },
    );
  }
  const { path } = await context.params;
  const target = desktopApiTarget(configuration.apiUrl, request, path);
  const method = request.method.toUpperCase();
  const body = ["GET", "HEAD"].includes(method)
    ? undefined
    : await request.arrayBuffer();
  const upstream = await fetch(target, {
    method,
    headers: forwardedRequestHeaders(request, configuration.secret),
    body,
    redirect: "manual",
    cache: "no-store",
  });
  return new Response(upstream.body, {
    status: upstream.status,
    headers: forwardedResponseHeaders(upstream.headers),
  });
}

export const GET = forward;
export const POST = forward;
export const PUT = forward;
export const PATCH = forward;
export const DELETE = forward;
export const HEAD = forward;
