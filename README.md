# CompactSessionSecurityTokens

When using WIF to implement federated authentication for a web site (i.e. WS-Federation), the initial security token from an identity provider (IdP) is validated by WIF and exchanged for a session security token (presumably more lightweight and easier to verify cryptographically).
In order to reduce the size of your tokens (and the resulting cookies), you can turn on Reference mode, which moves the bulk of the session security token into an [in-memory cache](https://msdn.microsoft.com/en-us/library/system.identitymodel.tokens.sessionsecuritytokencache(v=vs.110).aspx).
Unfortunately, the default implementation [doesn't play nicely with farms](https://msdn.microsoft.com/en-us/library/hh545457%28v=vs.110%29.aspx) and so you have to resort to writing your own token cache.

Alternatively, you can reduce the size of your session security tokens by using abbreviated claim-type identifiers. You can configure the CompactSessionSecurityTokenHandler to map any given claim type identifier (usually some kind of URI) into a more compact format.

For example, you could map "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" to "upn".
Depending on the number of claims in your token, this can shrink it (and consequently your Auth* cookies) significantly.

## Example configuration (web.config)

```xml
<configuration>
    <system.web>
        <!-- Configure the machine key for this web application (should be the same on all machines in a farm) -->
        <machineKey
			validationKey="ECD41BF951CC703E31FA1B9650AE605FCDA83E52330884D4"
			decryptionKey="ECD41BF951CC703E31FA1B9650AE605FCDA83E52330884D4"
		/>
    </system.web>
    <system.identityModel>
        <identityConfiguration>
            <securityTokenHandlers>
                <!-- First, remove the old session security token handler -->
                <remove type="System.IdentityModel.Tokens.SessionSecurityTokenHandler, System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" />

                <!-- Now add the compact session security token handler that uses machine keys -->
                <add type="CompactSessionSecurityTokens.CompactMachineKeySessionSecurityTokenHandler, CompactSessionSecurityTokens">
                    <mappings>
                        <claimType from="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" to="ni" />
                        <claimType from="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" to="upn" />
                        <claimType from="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" to="gnm" />
                    </mappings>

                    <!-- You can also configure token lifetime here -->
                    <sessionTokenRequirement lifetime="15:00:00" />
				</add>
            </securityTokenHandlers>
        </identityConfiguration>
    </system.identityModel>
</configuration>
```