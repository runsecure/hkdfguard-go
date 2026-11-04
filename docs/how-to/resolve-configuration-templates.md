# Resolve configuration templates from protected caches

This page fills the `${name}` items in a template, such as a connection string or a configuration
file, with secrets from HkdfGuard's protected caches. Everything it uses is in one module,
`integration/configurationresolver`. That module is the Go port of .NET's
`HkdfGuard.Integration.ConfigurationResolver`, together with the parts of
[ConfigurationResolver](https://github.com/runsecure/configurationresolver-dotnet) that it needs:
the token, the reader, the resolver and the value-provider contract. It depends only on the root
module.

Any `hkdfguard.ProtectedReadOnlyCache` can supply the values:

- a `cache.Cache`, a `cache.Collection` or a `cache/filepersecret` cache
- an `encryptedconfig.Reader`, for secrets a pipeline encrypted into your configuration
- a remote secret store's cache: `cache/awssecretsmanager`, `cache/azurekeyvault`,
  `cache/googlesecretmanager` or `cache/hashicorpvault`

## 1. Install

```sh
go get github.com/runsecure/hkdfguard-go/integration/configurationresolver
```

Add the module for your cache too, such as `github.com/runsecure/hkdfguard-go/cache/hashicorpvault`.
Everything below is in the package `configurationresolver`.

## 2. Resolve a template

A template's key is the cache's name for the value, unchanged. For a remote cache that includes the
`secret#key` form, so `${app-config#password}` is the `password` key of the secret `app-config`.

```go
// secrets is any hkdfguard.ProtectedReadOnlyCache, such as a hashicorpvault cache.
template := "Host=db.internal;Username=${app-config#user};Password=${app-config#password}"

token := configurationresolver.NewDefaultToken()
reader, _ := configurationresolver.NewConfigurationItemReader(token)
reader.ReadKeysString(template)

resolver, err := configurationresolver.NewConfigurationResolverBuilder().
	WithToken(token).
	WithReader(reader).
	AddProtectedCache(secrets).
	Build()
if err != nil {
	return err
}

connectionString := make([]byte, 1024)
defer hkdfguard.Wipe(connectionString)
n, err := resolver.Resolve(ctx, []byte(template), connectionString)
if err != nil {
	return err
}
// use connectionString[:n]
```

The resolver looks up only the keys the reader read from the template. Read the template from a
trusted source, since it decides which secrets are revealed. Write `$${name}` for the literal text
`${name}`.

A missing value fails with a `*configurationresolver.ConfigurationKeyError` whose `Code` is
`KeyNotFound`, and a destination that is too small with `ErrDestinationTooSmall`. A cache's own
error, such as a remote store refusing access, is returned unchanged.

> **Security:** Each value is decrypted straight into the destination, or into a scratch buffer that
> is wiped once the value is copied out. It never becomes a Go string. If resolving fails, the
> resolver wipes the whole destination. The `ConfigurationKeyError` message holds only the item's
> position; its `Key` comes from the template, so treat it as untrusted before logging it.

### Prefetch, if you want fetches up front

Every lookup passes your `context.Context` to the cache, so a remote cache's first fetch of a
secret happens during `Resolve`, bounded by that context. To fetch everything before resolving -
at startup, say, or to separate network failures from resolution - prefetch the reader's keys:

```go
provider, err := configurationresolver.NewProtectedCacheValueProvider(secrets)
if err != nil {
	return err
}
if err := provider.Prefetch(ctx, reader); err != nil {
	return err
}
resolver, err := configurationresolver.NewConfigurationItemResolver(token, reader, provider)
```

Prefetching asks for each key once. A key the cache doesn't have is skipped then, and reported by
`Resolve`. For a local cache, prefetching does nothing and you can leave it out.

## 3. Combine it with other providers

Pass several providers, highest priority first. The first one that has a key supplies its value.
Any `ValueProvider` works. For one over your own settings that aren't secret, implement
`TryGetBytes` and `TryGetByteCount` (a `ByteValueProvider`) and wrap it in `ValueProviderBase`:

```go
resolver, err := configurationresolver.NewConfigurationResolverBuilder().
	WithReader(reader).
	AddProtectedCache(secrets).
	AddValueProvider(configurationresolver.ValueProviderBase{ByteValueProvider: mySettings}).
	Build()
```

## 4. Keep templates in the caches themselves

`ResolvingProtectedCacheCollection` resolves templates for you, on lookup. It works like
`cache.Collection`: you add sources, and it checks them in order. When the value it finds holds
items, it resolves them from the same sources, encrypts the result under your key ring, and keeps
it. Later lookups only decrypt the kept result. A value without items is answered by its source,
unchanged.

Because the collection is itself a `hkdfguard.ProtectedReadOnlyCache`, anything that reads a cache
can read resolved templates without knowing they were templates:

```go
// ring is your application's key ring. local holds, say, the encrypted value
// "Host=db.internal;Username=${app-config#user};Password=${app-config#password}"
// under the name "orders.connection-string"; vault is a hashicorpvault cache.
secrets, err := configurationresolver.NewResolvingProtectedCacheCollection(ring, configurationresolver.ResolvingOptions{})
if err != nil {
	return err
}
secrets.Add(local).Add(vault)

maxLength, _, err := secrets.MaxDecryptedLength(ctx, "orders.connection-string")
if err != nil {
	return err
}
connectionString := make([]byte, maxLength)
defer hkdfguard.Wipe(connectionString)
n, err := secrets.Decrypt(ctx, "orders.connection-string", connectionString)
```

Items can also come from value providers that are asked after every source, for values that aren't
secret:

```go
secrets.Add(local).
	Add(vault).
	AddValueProvider(configurationresolver.ValueProviderBase{ByteValueProvider: mySettings})
```

> **Security:** Any value in any source that holds `${...}` is a template, and a template can name
> any value in any source. Add only sources you trust as much as the secrets they can reach.

Some things to know:

- **Resolved values are kept until you invalidate them.** A value a template uses can change, for
  example through an `AddOrUpdate` or a rotated remote secret. When it does, call
  `Invalidate(name)` with the template's name, or `Clear()`. The next lookup resolves it again. A
  resolution already under way when you call either doesn't keep its result.
- **Items are resolved one level deep.** An item whose value is itself a template inserts that
  template's text unresolved.
- **A template that names a missing value fails** with a `*ConfigurationKeyError` on lookup, rather
  than reporting the template's name missing. A template that resolves to nothing is reported
  missing, as an empty value can't be cached.
- **Names match exactly**, as the sources' own names may. The collection keeps `Db` and `db` apart,
  even though HkdfGuard's caches otherwise ignore ASCII case.
- **Resolved values are capped** at `MaxResolvedLength` bytes, 1 MiB by default. A longer one fails
  with `ErrResolvedValueTooLong`. Set it, and the token, through `ResolvingOptions`.
- **Add every source and provider before the first lookup.** `Add` and `AddValueProvider` panic on
  nil.

## Values as strings

`ValueProvider.TryGetValue` returns a value as a Go string, which can't be wiped. The resolver never
calls it, and `ProtectedCacheValueProvider` fails it with `ErrStringValuesNotAllowed`. When a caller
truly needs strings, opt in:

```go
provider = provider.WithAllowStringValues(true)
```

## Differences from .NET

- **UTF-8 only.** Go strings are UTF-8, so there is one `Resolve`, over bytes, and no char
  overloads; `TryGetChar` is `TryGetBytes`. An item's `SourceIndex` is a byte index.
- **Contexts, not async.** Every member that may reach a cache takes a `context.Context`, which is
  passed on to it. There are no `...Async` members: `PrefetchAsync` is `Prefetch` and
  `PrefetchKeys`, and the collection's `DecryptAsync` and `GetMaxDecryptedLengthAsync` are its
  `Decrypt` and `MaxDecryptedLength`.
- **Errors, not exceptions.** `ConfigurationKeyException` is `*ConfigurationKeyError`, and its
  `ConfigurationKeyError` enum is `ConfigurationKeyErrorCode` (`KeyNotAllowed`, `KeyNotFound`,
  `KeyValueUnstable`, `KeyCycle`), printed with the .NET names. The destination's
  `ArgumentException` is `ErrDestinationTooSmall`; the collection's `InvalidOperationException`s
  are `ErrResolvedValueTooLong` and `ErrStringValuesNotAllowed`. Invalid arguments to a
  constructor are returned as errors; the builder returns the first from `Build`.
- **Go names.** `ConfigurationItemTokenBase` and `DefaultToken` are `ConfigurationItemToken` and
  `NewDefaultToken`, with `""` for no escape sequence. The resolver needs only a reader's keys, the
  `KeyReader` interface; `ConfigurationItemReader` is the concrete reader, with
  `ReadKeys([]byte)`, `ReadKeysString`, `ReadKeysAll` and `ReadKeysFrom(io.Reader)`, which detects
  byte order marks but takes no encoding. `init` properties are `With...` methods that return a
  copy, the collection's `Token` and `MaxResolvedLength` are `ResolvingOptions`, and the
  `AddProtectedCache` extension method is a method of the builder.
- **`ValueProviderBase` is a wrapper.** Go has no base classes, so it is a struct around a
  `ByteValueProvider` (`TryGetBytes` and `TryGetByteCount`), adding `TryGetValue`.
- Only the parts of ConfigurationResolver this integration uses are ported. The file-secret,
  environment-variable and dictionary providers, `StringValueProviderBase`, `SecretBuffer`, and the
  Microsoft.Extensions.Configuration support are not.
