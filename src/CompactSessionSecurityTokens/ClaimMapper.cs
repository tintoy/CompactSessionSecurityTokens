using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace CompactSessionSecurityTokens
{

	/// <summary>
	///		Maps between compact and expanded claims.
	/// </summary>
    sealed class ClaimMapper
    {
		/// <summary>
		///		Map from expanded claim identifiers to compacted claim identifiers.
		/// </summary>
		readonly Dictionary<string, string> _compactionMap = new Dictionary<string, string>();

		/// <summary>
		///		Map from compacted claim identifiers to expanded claim identifiers.
		/// </summary>
		readonly Dictionary<string, string> _expansionMap = new Dictionary<string, string>();

		/// <summary>
		///		Create a new claim mapper.
		/// </summary>
		public ClaimMapper()
		{
		}

		/// <summary>
		///		Create a new claim mapper.
		/// </summary>
		/// <param name="claimCompactionMap">
		///		Mappings from expanded claim type identifiers to compacted ones.
		/// </param>
		public ClaimMapper(IReadOnlyDictionary<string, string> claimCompactionMap)
		{
			if (claimCompactionMap == null)
				throw new ArgumentNullException(nameof(claimCompactionMap));

			AddMappings(claimCompactionMap);
		}

		/// <summary>
		///		Map from expanded claim identifiers to compacted claim type identifiers.
		/// </summary>
		public IReadOnlyDictionary<string, string> CompactionMap => _compactionMap;

		/// <summary>
		///		Map from compacted claim identifiers to expanded claim identifiers.
		/// </summary>
		public IReadOnlyDictionary<string, string> ExpansionMap => _expansionMap;

		/// <summary>
		///		Add the specified mappings to the claim mapper.
		/// </summary>
		/// <param name="claimCompactionMap">
		///		Mappings from expanded claim type identifiers to compacted ones.
		/// </param>
		public void AddMappings(IReadOnlyDictionary<string, string> claimCompactionMap)
		{
			if (claimCompactionMap == null)
				throw new ArgumentNullException(nameof(claimCompactionMap));

			foreach (KeyValuePair<string, string> compactionMapping in claimCompactionMap)
			{
				if (_compactionMap.ContainsKey(compactionMapping.Key))
				{
					throw new ArgumentException(
						$"A mapping already exists for claim type '{compactionMapping.Key}'.",
						nameof(claimCompactionMap)
					);
				}

				_compactionMap.Add(compactionMapping.Key, compactionMapping.Value);

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
		///		Remove all configured mappings.
		/// </summary>
		public void ClearMappings()
		{
			_compactionMap.Clear();
			_expansionMap.Clear();
		}

		/// <summary>
		///		Replace claim mapper's configuration with the specified mappings.
		/// </summary>
		/// <param name="claimCompactionMap">
		///		Mappings from expanded claim type identifiers to compacted ones.
		/// </param>
		public void ReplaceMappings(IReadOnlyDictionary<string, string> claimCompactionMap)
		{
			if (claimCompactionMap == null)
				throw new ArgumentNullException(nameof(claimCompactionMap));

			ClearMappings();
			AddMappings(claimCompactionMap);
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
		public Claim ExpandClaim(Claim claim)
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
		///		Expand a claim type.
		/// </summary>
		/// <param name="claimType">
		///		The (potentially compacted) claim type.
		/// </param>
		/// <returns>
		///		The expanded claim type (or the input claim type if it is already expanded).
		/// </returns>
		public string ExpandClaimType(string claimType)
		{
			if (String.IsNullOrWhiteSpace(claimType))
				throw new ArgumentException("Argument cannot be null, empty, or composed entirely of whitespace: 'incomingClaimType'.", nameof(claimType));

			string fullClaimType;
			if (_expansionMap.TryGetValue(claimType, out fullClaimType))
				return fullClaimType;

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
		public Claim CompactClaim(Claim claim)
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

		/// <summary>
		///		Compact a claim type.
		/// </summary>
		/// <param name="claimType">
		///		The (potentially expanded) claim type.
		/// </param>
		/// <returns>
		///		The compacted claim type (or the input claim type if it is already compacted).
		/// </returns>
		public string CompactClaimType(string claimType)
		{
			if (String.IsNullOrWhiteSpace(claimType))
				throw new ArgumentException("Argument cannot be null, empty, or composed entirely of whitespace: 'fullClaimType'.", nameof(claimType));

			string compactedClaimType;
			if (_compactionMap.TryGetValue(claimType, out compactedClaimType))
				return compactedClaimType;

			return claimType;
		}
	}
}
