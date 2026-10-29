import { expect } from "bun:test"
import { Context, Effect, Layer } from "effect"
import { HttpEffect, HttpRouter, HttpServer } from "effect/http"
import { tmpdirScoped } from "../../core/test/fixture/tmpdir"
import { it } from "../../core/test/lib/effect"
import { createRoutes } from "../src/routes"

it.live("integration policy filters /connect and blocks denied integrations and providers", () =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped("opencode-integration-policy-")
    const context = yield* Layer.build(
      createRoutes({
        password: "secret",
        database: { path: ":memory:" },
        models: { fetch: false },
        fs: { filewatcher: false },
        config: {
          directory: tmp.path,
          project: false,
          content: JSON.stringify({
            providers: {
              custom: {
                name: "Configured Custom Provider",
                package: "@opencode/ai/providers/openai-compatible",
                settings: { apiKey: "secret" },
                models: { chat: {} },
              },
            },
            policies: [
              { action: "integration.connect", resource: "*", effect: "deny" },
              { action: "integration.connect", resource: "opencode", effect: "allow" },
              { action: "integration.use", resource: "*", effect: "deny" },
              { action: "integration.use", resource: "opencode#org_01M3CAP8H43Z49CER6NT0Y3ZF1", effect: "allow" },
            ],
          }),
        },
      }).pipe(Layer.provide(HttpServer.layerServices)),
    )
    const handler = Context.get(context, HttpRouter.HttpRouter)
      .asHttpEffect()
      .pipe(HttpEffect.toWebHandlerWith(context))
    const request = (method: "GET" | "POST", route: string, body?: unknown) =>
      Effect.promise(async (signal) => {
        const url = new URL(route, "http://opencode.local")
        url.searchParams.set("location[directory]", tmp.path)
        const response = await handler(
          new Request(url, {
            method,
            headers: {
              authorization: `Basic ${btoa("opencode:secret")}`,
              ...(body === undefined ? {} : { "content-type": "application/json" }),
            },
            body: body === undefined ? undefined : JSON.stringify(body),
            signal,
          }),
        )
        return { status: response.status, body: response.status === 204 ? undefined : await response.json() }
      })

    const integrations = yield* request("GET", "/api/integration")
    expect(integrations.status).toBe(200)
    expect(integrations.body.data.map((integration: { id: string }) => integration.id)).toEqual(["opencode"])

    const denied = yield* request("POST", "/api/integration/anthropic/connect/key", { key: "sk-test" })
    expect(denied.status).toBe(400)
    expect(denied.body).toMatchObject({ _tag: "InvalidRequestError", kind: "integration_policy" })
    const credential = yield* request("POST", "/api/credential", {
      integrationID: "anthropic",
      value: { type: "key", key: "sk-test" },
    })
    expect(credential.status).toBe(400)
    expect(credential.body).toMatchObject({ _tag: "InvalidRequestError", kind: "integration_policy" })
    expect((yield* request("GET", "/api/credential")).body.data).toEqual([])
    const wellknown = yield* request("POST", "/api/experimental/integration/wellknown", { url: "https://ai.acme.com" })
    expect(wellknown.body).toMatchObject({ kind: "integration_policy" })

    // The signed-out free tier and the authored provider are both denied.
    expect((yield* request("GET", "/api/provider")).body.data).toEqual([])
  }),
)
