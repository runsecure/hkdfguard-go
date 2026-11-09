// Package configurationresolver fills the ${name} items in a template - a connection string, a
// configuration file - with secrets from HkdfGuard's protected caches. It is the Go port of the
// .NET HkdfGuard.Integration.ConfigurationResolver, together with the parts of ConfigurationResolver
// (https://github.com/runsecure/configurationresolver-dotnet) that it uses:
//
//   - ConfigurationItemToken: the start, end and escape sequences of an item; NewDefaultToken
//     gives "${", "}" and "$", so "$${name}" is the literal text "${name}".
//   - ConfigurationItemReader: reads a trusted template's keys. A resolver looks up only those.
//   - ConfigurationItemResolver: copies a template to a destination, replacing each item with its
//     value, and wipes the destination if it fails. ConfigurationResolverBuilder builds one.
//   - ValueProvider: where values come from. CompositeValueProvider asks several in order;
//     ValueProviderBase adds TryGetValue to a provider that only writes bytes.
//
// and HkdfGuard's own part:
//
//   - ProtectedCacheValueProvider: a ValueProvider over any hkdfguard.ProtectedReadOnlyCache - a
//     cache.Cache, a cache.Collection, a cache/filepersecret cache, an encryptedconfig.Reader or a
//     remote secret store's cache. A template's key is the cache's name, unchanged, so a remote
//     cache's "app-config#password" form works as it is.
//   - ResolvingProtectedCacheCollection: a hkdfguard.ProtectedReadOnlyCache over several sources
//     that resolves a value holding items on its first lookup, from those same sources, and keeps
//     the result encrypted under a KeyRing.
//
// Values are written by their provider straight into the destination, or through a scratch buffer
// that is wiped once the value is copied out, and are never Go strings: TryGetValue, the one member
// that returns a string, refuses on a ProtectedCacheValueProvider unless WithAllowStringValues is
// set, and a resolver never calls it.
//
// Go strings are UTF-8, so where .NET resolves both chars and UTF-8 bytes this port resolves bytes
// only, and an item's index (ConfigurationKeyError.SourceIndex) is a byte index. Every member that
// may reach a cache takes the caller's context.Context, which is passed on to the cache.
package configurationresolver
