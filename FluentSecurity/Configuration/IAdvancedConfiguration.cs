using System;
using System.Collections.Generic;

namespace FluentSecurity.Configuration
{
	public interface IAdvancedConfiguration
	{
		IDictionary<Type, object> ContextBuilders { get; }
		//Action<dynamic> ContextDataBuilder { get; }
	}
}