//! Rule precedence logic — determines which rule wins when multiple match.

use std::cmp::Ordering;

use crate::verdict::{PolicyScope, Verdict};

/// Information needed to compare two rule matches for precedence.
#[derive(Debug, Clone)]
pub struct RulePrecedence {
    /// The scope of the policy the rule belongs to.
    pub scope: PolicyScope,
    /// The verdict of the rule.
    pub verdict: Verdict,
    /// Priority value (higher = more important).
    pub priority: i32,
    /// Load order index (lower = loaded first, used for stable ordering).
    pub load_order: usize,
}

/// Compare two rules for precedence.
///
/// Returns `Ordering::Greater` if `a` should take precedence over `b`.
///
/// Precedence rules (applied in order):
/// 1. More specific scope wins (Override > Project > Team > Agent > Global)
/// 2. Higher priority value wins
/// 3. Within the same scope and priority, deny beats non-deny
/// 4. First loaded wins (lower load_order)
pub fn compare_precedence(a: &RulePrecedence, b: &RulePrecedence) -> Ordering {
    // 1. More specific scope wins.
    let scope_cmp = a.scope.cmp(&b.scope);
    if scope_cmp != Ordering::Equal {
        return scope_cmp;
    }

    // 2. Higher priority wins.
    let prio_cmp = a.priority.cmp(&b.priority);
    if prio_cmp != Ordering::Equal {
        return prio_cmp;
    }

    // 3. Within same scope and priority, deny beats non-deny.
    let a_deny = a.verdict == Verdict::Deny;
    let b_deny = b.verdict == Verdict::Deny;
    if a_deny && !b_deny {
        return Ordering::Greater;
    }
    if !a_deny && b_deny {
        return Ordering::Less;
    }

    // 4. First loaded wins (lower load_order = higher precedence).
    b.load_order.cmp(&a.load_order)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn more_specific_scope_wins() {
        let a = RulePrecedence {
            scope: PolicyScope::Project,
            verdict: Verdict::Allow,
            priority: 0,
            load_order: 0,
        };
        let b = RulePrecedence {
            scope: PolicyScope::Global,
            verdict: Verdict::Allow,
            priority: 0,
            load_order: 0,
        };
        assert_eq!(compare_precedence(&a, &b), Ordering::Greater);
    }

    #[test]
    fn deny_beats_allow_same_scope() {
        let a = RulePrecedence {
            scope: PolicyScope::Global,
            verdict: Verdict::Deny,
            priority: 0,
            load_order: 1,
        };
        let b = RulePrecedence {
            scope: PolicyScope::Global,
            verdict: Verdict::Allow,
            priority: 0,
            load_order: 0,
        };
        assert_eq!(compare_precedence(&a, &b), Ordering::Greater);
    }

    #[test]
    fn higher_priority_wins_same_scope_same_verdict() {
        let a = RulePrecedence {
            scope: PolicyScope::Team,
            verdict: Verdict::Allow,
            priority: 10,
            load_order: 1,
        };
        let b = RulePrecedence {
            scope: PolicyScope::Team,
            verdict: Verdict::Allow,
            priority: 5,
            load_order: 0,
        };
        assert_eq!(compare_precedence(&a, &b), Ordering::Greater);
    }

    #[test]
    fn first_loaded_wins_tie() {
        let a = RulePrecedence {
            scope: PolicyScope::Global,
            verdict: Verdict::Allow,
            priority: 0,
            load_order: 0,
        };
        let b = RulePrecedence {
            scope: PolicyScope::Global,
            verdict: Verdict::Allow,
            priority: 0,
            load_order: 5,
        };
        assert_eq!(compare_precedence(&a, &b), Ordering::Greater);
    }

    #[test]
    fn override_scope_beats_everything() {
        let a = RulePrecedence {
            scope: PolicyScope::Override,
            verdict: Verdict::Allow,
            priority: 0,
            load_order: 100,
        };
        let b = RulePrecedence {
            scope: PolicyScope::Project,
            verdict: Verdict::Deny,
            priority: 100,
            load_order: 0,
        };
        assert_eq!(compare_precedence(&a, &b), Ordering::Greater);
    }
}
