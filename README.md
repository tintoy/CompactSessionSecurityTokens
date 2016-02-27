# CompactSessionSecurityTokens

When using WIF to implement federated authentication for a web site (i.e. WS-Federation), the initial security token from an identity provider (IdP) is validated by WIF and exchanged for a session security token (presumably more lightweight and easier to verify cryptographically).
In order to reduce the size of your tokens (and the resulting cookies), you can turn on Reference mode, which moves the bulk of the session security token into an [in-memory cache](https://msdn.microsoft.com/en-us/library/system.identitymodel.tokens.sessionsecuritytokencache(v=vs.110).aspx).
Unfortunately, the default implementation [doesn't play nicely with farms](https://msdn.microsoft.com/en-us/library/hh545457%28v=vs.110%29.aspx) and so you have to resort to writing your own token cache.

Alternatively, you can reduce the size of your session security tokens by using abbreviated claim-type identifiers. You can configure the CompactSessionSecurityTokenHandler to map any given claim type identifier (usually some kind of URI) into a more compact format.

For example, you could map "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" to "upn".
Depending on the number of claims in your token, this can shrink it (and consequently your Auth* cookies) significantly.
