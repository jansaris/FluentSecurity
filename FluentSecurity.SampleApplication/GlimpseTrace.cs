using System.Collections.Generic;
using System.Linq;
using System.Web;
using Glimpse.AspNet.Extensibility;
using Glimpse.Core.Extensibility;

namespace FluentSecurity.SampleApplication
{
	public static class GlimpseTraceSetup
	{
		private static readonly object LockObject = new object();
		static GlimpseTraceSetup()
		{
			lock (LockObject)
			{
				System.Diagnostics.Trace.UseGlobalLock = true;
				var traceListeners = System.Diagnostics.Trace.Listeners;
				if (!traceListeners.OfType<GlimpseTraceListener>().Any())
					traceListeners.Add(new GlimpseTraceListener()); //Add trace listener if it isn't already configured
			}
		}

		public static void Register() {}
	}

	public class GlimpseTrace : AspNetTab
	{
		public const string TraceMessageStoreKey = "Glimpse.Trace.Messages";
		public const string FirstWatchStoreKey = "Glimpse.Trace.FirstWatch";
		public const string LastWatchStoreKey = "Glimpse.Trace.LastWatch";

		public override object GetData(ITabContext context)
		{
			var httpContext = context.GetRequestContext<HttpContextBase>();
			var messages = httpContext.Items[TraceMessageStoreKey] as IList<IList<string>>;
			if (messages == null) return null;

			return messages;
		}

		public override string Name
		{
			get { return "Trace"; }
		}

		public string HelpUrl
		{
			get { return "http://getGlimpse.com/Help/Plugin/Trace"; }
		}
	}
}