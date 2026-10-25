# Pinned CycloneDX 1.6 JSON schema

Stored gzipped (`gzip -9 -n`) so the repository formatter (oxfmt via lint-staged) cannot rewrite
the bytes; the sha256 below is of the **decompressed** file, as published.

| File                               | sha256 (decompressed)                                              |
| ---------------------------------- | ------------------------------------------------------------------ |
| `bom-1.6.SNAPSHOT.schema.json.gz`  | `83821ba49aa366ad1f1d16c34837d05edd010f036f652e310db1c77d57b37c58` |
| `spdx.SNAPSHOT.schema.json.gz`     | `4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359` |
| `jsf-0.82.SNAPSHOT.schema.json.gz` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |

Source: npm package `@cyclonedx/cyclonedx-library@10.3.0`, directory `res/schema/`
(`npm pack @cyclonedx/cyclonedx-library@10.3.0` on 2026-10-25, first attempt).
Tarball: `https://registry.npmjs.org/@cyclonedx/cyclonedx-library/-/cyclonedx-library-10.3.0.tgz`,
sha256 `9833bd949052eb18218dd64b13ad62d9246f7395eef01c66dad08fcbacf74f01`,
npm integrity `sha512-RIT28sp1U0PCHaaeF3yNRwk6Jig/XJ8UsYAVOMYaHQ+0VVOvsjcp0PTWQFLUqJFF8XMud+Kdq6G+wtDAh+QJFA==`.

The library ships the official CycloneDX schemas with `$ref` targets renamed to `*.SNAPSHOT.*`
while each referenced schema keeps its upstream `$id` (`http://cyclonedx.org/schema/spdx.schema.json`,
`.../jsf-0.82.schema.json`). `test/support.mjs` registers them under the referenced names in memory;
the files themselves are unmodified. Whether these bytes equal the CycloneDX specification
repository's `bom-1.6.schema.json` was **not checked** (GitHub raw content was not used).

Validation: Ajv 8 (draft-07, `strict: false` for the schema's non-standard keywords) with
`ajv-formats` and `ajv-formats-draft2019` (`iri-reference`, `idn-email`), as the library does.
