"""
Task 23: ABAC (Attribute-Based Access Control) Placeholder Implementation
"""

class ABACPolicy:
    """Attribute-Based Access Control Policy Engine"""
    
    def __init__(self):
        self.policies = []
    
    def add_policy(self, subject_attributes, resource_attributes, action, effect="allow"):
        """
        Add a policy rule
        
        Args:
            subject_attributes: dict of subject attributes (e.g., {"role": "admin", "department": "IT"})
            resource_attributes: dict of resource attributes (e.g., {"type": "document", "classification": "public"})
            action: action to be performed (e.g., "read", "write", "delete")
            effect: "allow" or "deny"
        """
        policy = {
            "subject": subject_attributes,
            "resource": resource_attributes,
            "action": action,
            "effect": effect
        }
        self.policies.append(policy)
        return policy
    
    def evaluate(self, subject_attributes, resource_attributes, action):
        """
        Evaluate access request against policies
        
        Args:
            subject_attributes: dict of subject attributes
            resource_attributes: dict of resource attributes
            action: action to be performed
            
        Returns:
            bool: True if access is allowed, False otherwise
        """
        for policy in self.policies:
            if self._match_policy(policy, subject_attributes, resource_attributes, action):
                return policy["effect"] == "allow"
        
        # Default deny
        return False
    
    def _match_policy(self, policy, subject_attrs, resource_attrs, action):
        """Check if attributes match policy"""
        # Check action match
        if policy["action"] != action:
            return False
        
        # Check subject attributes match
        for key, value in policy["subject"].items():
            if subject_attrs.get(key) != value:
                return False
        
        # Check resource attributes match
        for key, value in policy["resource"].items():
            if resource_attrs.get(key) != value:
                return False
        
        return True


def main():
    """Example usage"""
    print("Task 23: ABAC Implementation")
    
    # Create ABAC policy engine
    abac = ABACPolicy()
    
    # Add policies
    abac.add_policy(
        subject_attributes={"role": "admin"},
        resource_attributes={"type": "document"},
        action="read",
        effect="allow"
    )
    
    abac.add_policy(
        subject_attributes={"role": "user", "department": "HR"},
        resource_attributes={"type": "document", "classification": "public"},
        action="read",
        effect="allow"
    )
    
    # Test access requests
    print("\nTesting access requests:")
    
    # Admin reading document - should be allowed
    result1 = abac.evaluate(
        subject_attributes={"role": "admin"},
        resource_attributes={"type": "document"},
        action="read"
    )
    print(f"Admin reading document: {'ALLOWED' if result1 else 'DENIED'}")
    
    # User reading public document - should be allowed
    result2 = abac.evaluate(
        subject_attributes={"role": "user", "department": "HR"},
        resource_attributes={"type": "document", "classification": "public"},
        action="read"
    )
    print(f"HR user reading public document: {'ALLOWED' if result2 else 'DENIED'}")
    
    # User reading private document - should be denied (no matching policy)
    result3 = abac.evaluate(
        subject_attributes={"role": "user", "department": "HR"},
        resource_attributes={"type": "document", "classification": "private"},
        action="read"
    )
    print(f"HR user reading private document: {'ALLOWED' if result3 else 'DENIED'}")


if __name__ == "__main__":
    main()
