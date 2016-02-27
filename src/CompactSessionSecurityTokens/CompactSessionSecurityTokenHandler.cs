using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;

namespace CompactSessionSecurityTokens
{
	/// <summary>
	///		A <see cref="SessionSecurityTokenHandler"/> that generates tokens with compacted identifiers.
	/// </summary>
	public sealed class CompactSessionSecurityTokenHandler
		: SessionSecurityTokenHandler
	{
		/// <summary>
		///		The transformations to perform on session security cookies to protect them using the machine key specified in web.config.
		/// </summary>
		/// <remarks>
		///		Required for web farms.
		/// </remarks>
		static readonly ReadOnlyCollection<CookieTransform> MachineKeyCookieTransforms =
			new ReadOnlyCollection<CookieTransform>(new CookieTransform[]
			{
				new DeflateCookieTransform(),
				new MachineKeyTransform()
			});

		/// <summary>
		///		Map from expanded claim identifiers to compacted claim identifiers.
		/// </summary>
		readonly Dictionary<string, string>	_compactionMap = new Dictionary<string, string>();

		/// <summary>
		///		Map from compacted claim identifiers to expanded claim identifiers.
		/// </summary>
		readonly Dictionary<string, string>	_expansionMap = new Dictionary<string, string>();

		/// <summary>
		///		Create a new <see cref="CompactSessionSecurityTokenHandler"/>.
		/// </summary>
		/// <param name="useMachineKey">
		///		Use the machine key to protect cookies (required for use in web farms)?
		/// 
		///		If <c>true</c>, cookies are protected using 
		///		If <c>false</c>, cookies are protected using <see cref="ProtectedDataCookieTransform"/>.
		/// </param>
		/// <param name="claimCompactionMap">
		///		Mappings from outgoing (full) claim identifiers to compacted claim identifiers.
		/// </param>
		public CompactSessionSecurityTokenHandler(bool useMachineKey, IReadOnlyDictionary<string, string> claimCompactionMap)
			: base(transforms: useMachineKey ? MachineKeyCookieTransforms : DefaultCookieTransforms)
		{
			if (claimCompactionMap == null)
				throw new ArgumentNullException(nameof(claimCompactionMap));

			foreach (KeyValuePair<string, string> compactionMapping in claimCompactionMap)
			{
				_compactionMap[compactionMapping.Key] = compactionMapping.Value;

				if (_expansionMap.ContainsKey(compactionMapping.Value))
				{
					throw new ArgumentException(
						$"Multiple claim types map to compact claim type '{compactionMapping.Value}'.",
						nameof(claimCompactionMap)
					);
				}
				_expansionMap.Add(compactionMapping.Value, compactionMapping.Key);
			}
		}

		/// <summary>
		///		Map from expanded claim identifiers to compacted claim identifiers.
		/// </summary>
		public IReadOnlyDictionary<string, string> CompactionMap => _compactionMap;

		/// <summary>
		///		Map from compacted claim identifiers to expanded claim identifiers.
		/// </summary>
		public IReadOnlyDictionary<string, string> ExpansionMap => _expansionMap;

		/// <summary>
		///		Create a new <see cref="SessionSecurityToken"/>.
		/// </summary>
		/// <param name="principal">
		///		The <see cref="ClaimsPrincipal"/> whose claims will be used to populate the token.
		/// </param>
		/// <param name="context">
		///		A caller-defined context string.
		/// </param>
		/// <param name="endpointId">
		///		The identifier of the end-point to which the token is scoped.
		/// </param>
		/// <param name="validFrom">
		///		The time from which the token becomes valid.
		/// </param>
		/// <param name="validTo">
		///		The time after which the token is no longer valid.
		/// </param>
		/// <returns>
		///		The session security token.
		/// </returns>
		public override SessionSecurityToken CreateSessionSecurityToken(ClaimsPrincipal principal, string context, string endpointId, DateTime validFrom, DateTime validTo)
		{
			if (principal == null)
				throw new ArgumentNullException(nameof(principal));

			if (String.IsNullOrWhiteSpace(endpointId))
				throw new ArgumentException("Argument cannot be null, empty, or composed entirely of whitespace: 'endpointId'.", nameof(endpointId));
			
			ClaimsPrincipal compactedPrincipal = new ClaimsPrincipal(
				principal.Identities.Select(
					identity => new ClaimsIdentity(
						identity.Claims.Select(
							claim => CompactClaim(claim)
						),
						identity.AuthenticationType,
						CompactClaimType(identity.NameClaimType),
						CompactClaimType(identity.RoleClaimType)
					)
				)
			);

			return base.CreateSessionSecurityToken(compactedPrincipal, context, endpointId, validFrom, validTo);
		}

		/// <summary>
		///		Validate the specified <see cref="SessionSecurityToken"/>.
		/// </summary>
		/// <param name="token">
		///		The <see cref="SessionSecurityToken"/> to validate.
		/// </param>
		/// <returns>
		///		A collection of <see cref="ClaimsIdentity">claims identities</see> containing the claims that comprise the token.
		/// </returns>
		public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
		{
			if (token == null)
				throw new ArgumentNullException(nameof(token));

			ReadOnlyCollection<ClaimsIdentity> compactedClaimsIdentities = base.ValidateToken(token);

			ReadOnlyCollection<ClaimsIdentity> fullClaimsIdentities =
				compactedClaimsIdentities.Select(
					identity => new ClaimsIdentity(
						identity.Claims.Select(
							claim => ExpandClaim(claim)
						),
						identity.AuthenticationType,
						ExpandClaimType(identity.NameClaimType),
						ExpandClaimType(identity.RoleClaimType)
					)
				)
				.ToList()

				.AsReadOnly();

			return fullClaimsIdentities;
		}

		/// <summary>
		///		Expand a claim type.
		/// </summary>
		/// <param name="claimType">
		///		The (potentially compacted) claim type.
		/// </param>
		/// <returns>
		///		The expanded claim type (or the input claim type if it is already expanded).
		/// </returns>
		string ExpandClaimType(string claimType)
		{
			if (String.IsNullOrWhiteSpace(claimType))
				throw new ArgumentException("Argument cannot be null, empty, or composed entirely of whitespace: 'incomingClaimType'.", nameof(claimType));

			string fullClaimType;
			if (_expansionMap.TryGetValue(claimType, out fullClaimType))
				return fullClaimType;

			return claimType;
		}

		/// <summary>
		///		Expand a claim's type.
		/// </summary>
		/// <param name="claim">
		///		The (potentially compacted) claim .
		/// </param>
		/// <returns>
		///		The expanded claim (or the input claim if its type is already expanded).
		/// </returns>
		Claim ExpandClaim(Claim claim)
		{
			if (claim == null)
				throw new ArgumentNullException(nameof(claim));

			string expandedClaimType = ExpandClaimType(claim.Type);
			if (expandedClaimType == null)
				return claim;

			return new Claim(
				expandedClaimType,
				claim.Value,
				claim.ValueType,
				claim.Issuer,
				claim.OriginalIssuer
			);
		}

		/// <summary>
		///		Compact a claim type.
		/// </summary>
		/// <param name="claimType">
		///		The (potentially expanded) claim type.
		/// </param>
		/// <returns>
		///		The compacted claim type (or the input claim type if it is already compacted).
		/// </returns>
		string CompactClaimType(string claimType)
		{
			if (String.IsNullOrWhiteSpace(claimType))
				throw new ArgumentException("Argument cannot be null, empty, or composed entirely of whitespace: 'fullClaimType'.", nameof(claimType));

			string compactedClaimType;
			if (_compactionMap.TryGetValue(claimType, out compactedClaimType))
				return compactedClaimType;

			return claimType;
		}

		/// <summary>
		///		Compact a claim's type.
		/// </summary>
		/// <param name="claim">
		///		The (potentially expanded) claim .
		/// </param>
		/// <returns>
		///		The compacted claim (or the input claim if its type is already compacted).
		/// </returns>
		Claim CompactClaim(Claim claim)
		{
			if (claim == null)
				throw new ArgumentNullException(nameof(claim));

			string compactedClaimType = CompactClaimType(claim.Type);
			if (compactedClaimType == claim.Type)
				return claim;

			return new Claim(
				compactedClaimType,
				claim.Value,
				claim.ValueType,
				claim.Issuer,
				claim.OriginalIssuer
			);
		}
	}
}
