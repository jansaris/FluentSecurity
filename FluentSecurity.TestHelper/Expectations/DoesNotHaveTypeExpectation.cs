﻿using System;
using System.Linq.Expressions;
using FluentSecurity.Policy;

namespace FluentSecurity.TestHelper.Expectations
{
	public class DoesNotHaveTypeExpectation<TSecurityPolicy> : DoesNotHaveTypeExpectation where TSecurityPolicy : class, ISecurityPolicy
	{
		public Expression<Func<TSecurityPolicy, bool>> PredicateExpression { get; private set; }
		public Func<TSecurityPolicy, bool> Predicate { get; private set; }

		public DoesNotHaveTypeExpectation() : base(typeof(TSecurityPolicy), false)
		{
			PredicateExpression = securityPolicy => securityPolicy.GetPolicyType() == Type;
			Predicate = PredicateExpression.Compile();
		}

		public DoesNotHaveTypeExpectation(Expression<Func<TSecurityPolicy, bool>> predicateExpression) : base(typeof(TSecurityPolicy), true)
		{
			PredicateExpression = predicateExpression;
			Predicate = PredicateExpression.Compile();
		}

		protected override bool EvaluatePredicate(ISecurityPolicy securityPolicy)
		{
			var policy = securityPolicy as TSecurityPolicy;
			if (policy == null)
			{
				var lazyPolicy = securityPolicy as ILazySecurityPolicy;
				if (lazyPolicy != null && lazyPolicy.PolicyType == typeof(TSecurityPolicy))
					policy = lazyPolicy.Load() as TSecurityPolicy;
			}
			return policy != null && Predicate.Invoke(policy);
		}

		public override string GetPredicateDescription()
		{
			return PredicateExpression.ToString();
		}
	}

	public abstract class DoesNotHaveTypeExpectation : TypeExpectation
	{
		protected DoesNotHaveTypeExpectation(Type type, bool isPredicateExpectation) : base(type, isPredicateExpectation) {}
	}
}