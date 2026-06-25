// cloudflare:test の env に KV バインディングの型を与える。
declare module "cloudflare:test" {
  interface ProvidedEnv {
    SECRETS: KVNamespace;
  }
}
