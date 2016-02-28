using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.IdentityModel.Services.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Xml;

namespace CompactSessionSecurityTokens
{
	/// <summary>
	///		A <see cref="MachineKeySessionSecurityTokenHandler"/> that generates tokens with compacted identifiers.
	/// </summary>
	/// <remarks>
	///		Required for web farms.
	/// </remarks>
	public sealed class CompactMachineKeySessionSecurityTokenHandler
		: MachineKeySessionSecurityTokenHandler
	{
		/// <summary>
		///		Map from expanded claim identifiers to compacted claim identifiers.
		/// </summary>
		readonly ClaimMapper _mapper;

		/// <summary>
		///		Create a new <see cref="CompactMachineKeySessionSecurityTokenHandler"/>.
		/// </summary>
		public CompactMachineKeySessionSecurityTokenHandler()
		{
			// Mappings will come from configuration.
			_mapper = new ClaimMapper();
		}

		/// <summary>
		///		Create a new <see cref="CompactSessionSecurityTokenHandler"/>.
		/// </summary>
		/// <param name="claimCompactionMap">
		///		Mappings from expanded claim type identifiers to compacted ones.
		/// </param>
		public CompactMachineKeySessionSecurityTokenHandler(IReadOnlyDictionary<string, string> claimCompactionMap)
		{
			if (claimCompactionMap == null)
				throw new ArgumentNullException(nameof(claimCompactionMap));

			_mapper = new ClaimMapper(claimCompactionMap);
		}

		/// <summary>
		///		Map from expanded claim type identifiers to compacted claim identifiers.
		/// </summary>
		public IReadOnlyDictionary<string, string> CompactionMap => _mapper.CompactionMap;

		/// <summary>
		///		Map from compacted claim type identifiers to expanded claim identifiers.
		/// </summary>
		public IReadOnlyDictionary<string, string> ExpansionMap => _mapper.ExpansionMap;

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
							claim => _mapper.CompactClaim(claim)
						),
						identity.AuthenticationType,
						_mapper.CompactClaimType(identity.NameClaimType),
						_mapper.CompactClaimType(identity.RoleClaimType)
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
							claim => _mapper.ExpandClaim(claim)
						),
						identity.AuthenticationType,
						_mapper.ExpandClaimType(identity.NameClaimType),
						_mapper.ExpandClaimType(identity.RoleClaimType)
					)
				)
				.ToList()
				.AsReadOnly();

			return fullClaimsIdentities;
		}

		/// <summary>
		///		Load custom configuration (if any) from the application configuration.
		/// </summary>
		/// <param name="customConfiguration">
		///		An <see cref="XmlNodeList"/> containing the children (if any) of the security token handler's configuration element.
		/// </param>
		public override void LoadCustomConfiguration(XmlNodeList customConfiguration)
		{
			if (customConfiguration == null)
				throw new ArgumentNullException(nameof(customConfiguration));

			base.LoadCustomConfiguration(customConfiguration);

			IReadOnlyDictionary<string, string> mappings = MapperConfiguration.GetCompactionMappings(customConfiguration);
			if (mappings != null)
				_mapper.ReplaceMappings(mappings);
		}
	}
}
