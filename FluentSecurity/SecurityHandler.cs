using System;
using System.Diagnostics;
using System.Linq;
using System.Web.Mvc;
using FluentSecurity.Internals;
using FluentSecurity.Policy.ViolationHandlers;
using FluentSecurity.ServiceLocation;

namespace FluentSecurity
{
	public static class Log
	{
		public static Action<SecurityRuntimeEvent> RuntimeEventListener;

		public static void RuntimeEvent(Func<string> message, ISecurityContext securityContext)
		{
			RuntimeEvent(e => e.Message = message.Invoke(), securityContext);
		}

		public static void RuntimeEvent(Action<SecurityRuntimeEvent> @event, ISecurityContext securityContext)
		{
			if (RuntimeEventListener != null)
			{
				var runtimeEvent = new SecurityRuntimeEvent
				{
					ContextId = securityContext.Id
				};
				@event.Invoke(runtimeEvent);
				RuntimeEventListener.Invoke(runtimeEvent);
			}
		}

		public static void TimingOf(Action action, Func<string> message, ISecurityContext securityContext)
		{
			if (RuntimeEventListener != null)
			{
				var stopwatch = new Stopwatch();
				stopwatch.Start();
				action.Invoke();
				stopwatch.Stop();
				RuntimeEvent(e =>
				{
					e.Message = message.Invoke();
					e.CompletedInMilliseconds = stopwatch.ElapsedMilliseconds;
				}, securityContext);
			} else action.Invoke();
		}

		public static TResult TimingOf<TResult>(Func<TResult> action, Func<string> message, ISecurityContext securityContext)
		{
			if (RuntimeEventListener != null)
			{
				var stopwatch = new Stopwatch();
				stopwatch.Start();
				var result = action.Invoke();
				stopwatch.Stop();
				RuntimeEvent(e =>
				{
					e.Message = message.Invoke();
					e.CompletedInMilliseconds = stopwatch.ElapsedMilliseconds;
				}, securityContext);
				return result;
			}
			return action.Invoke();
		}
	}

	public class SecurityRuntimeEvent
	{
		public Guid ContextId { get; set; }
		public string Message { get; set; }
		public long? CompletedInMilliseconds { get; set; }
	}

	public class SecurityHandler : ISecurityHandler
	{
		public ActionResult HandleSecurityFor(string controllerName, string actionName, ISecurityContext securityContext)
		{
			if (controllerName.IsNullOrEmpty()) throw new ArgumentException("Controllername must not be null or empty", "controllerName");
			if (actionName.IsNullOrEmpty()) throw new ArgumentException("Actionname must not be null or empty", "actionName");
			if (securityContext == null) throw new ArgumentNullException("securityContext", "Security context must not be null");

			Log.RuntimeEvent(() => "Handling security for {0} action {1}.".FormatWith(controllerName, actionName), securityContext);

			var configuration = ServiceLocator.Current.Resolve<ISecurityConfiguration>();
			
			var policyContainer = configuration.PolicyContainers.GetContainerFor(controllerName, actionName);
			if (policyContainer != null)
			{
				var results = Log.TimingOf(
					() => policyContainer.EnforcePolicies(securityContext),
					() => "Enforced all policies.", securityContext);

				if (results.Any(x => x.ViolationOccured))
				{
					var result = results.First(x => x.ViolationOccured);
					Log.RuntimeEvent(() => "Policy violation occured! {0}.".FormatWith(result.PolicyType.FullName), securityContext);
					var policyViolationException = new PolicyViolationException(result);
					var violationHandlerSelector = ServiceLocator.Current.Resolve<IPolicyViolationHandlerSelector>();
					var matchingHandler = violationHandlerSelector.FindHandlerFor(policyViolationException) ?? new ExceptionPolicyViolationHandler();
					Log.RuntimeEvent(() => "Handling policy violation with {0}.".FormatWith(matchingHandler.GetType().FullName), securityContext);
					return matchingHandler.Handle(policyViolationException);
				}
				Log.RuntimeEvent(() => "Success! All policies were met.", securityContext);
				return null;
			}

			if (configuration.Advanced.ShouldIgnoreMissingConfiguration)
			{
				Log.RuntimeEvent(() => "Missing configuration. Ignored.", securityContext);
				return null;
			}

			throw ExceptionFactory.CreateConfigurationErrorsException("Security has not been configured for controller {0}, action {1}".FormatWith(controllerName, actionName));
		}
	}
}