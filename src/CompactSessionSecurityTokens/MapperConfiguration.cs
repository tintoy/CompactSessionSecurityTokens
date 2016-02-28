using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;

namespace CompactSessionSecurityTokens
{
	/// <summary>
	///		Parsing logic for the configuration XML used by the compact security token handlers.
	/// </summary>
    static class MapperConfiguration
    {
		/// <summary>
		///		Parse the configuration for compaction mappings (if any) from the specified configuration XML.
		/// </summary>
		/// <param name="configurationXml">
		///		An <see cref="XmlNodeList"/> representing the custom configuration XML (if any) for a compact session security token handler.
		/// </param>
		/// <returns>
		///		A read-only dictionary of mappings or <c>null</c> if the configuration did not specify any mappings.
		/// </returns>
		public static IReadOnlyDictionary<string, string> GetCompactionMappings(XmlNodeList configurationXml)
		{
			if (configurationXml == null)
				throw new ArgumentNullException(nameof(configurationXml));
			
			XmlElement compactElement =
				configurationXml.OfType<XmlElement>()
					.FirstOrDefault(
						element => element.Name == "compact"
					);

			if (compactElement == null)
				return null;

			Dictionary<string, string> compactionMappings = new Dictionary<string, string>();
			foreach (XmlElement claimTypeElement in compactElement.SelectNodes("claimType"))
			{
				string fromClaimType = claimTypeElement.GetAttribute("from");
				if (String.IsNullOrWhiteSpace(fromClaimType))
					continue;

				string toClaimType = claimTypeElement.GetAttribute("to");
				if (String.IsNullOrWhiteSpace(toClaimType))
					continue;

				compactionMappings[fromClaimType] = toClaimType;
			}

			return compactionMappings;
		}
    }
}
