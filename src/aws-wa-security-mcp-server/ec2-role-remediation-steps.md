# EC2 IAM Role Remediation Steps

This document outlines the steps taken to remediate the overly permissive IAM role attached to the EC2 instance.

## Issue Identified

The EC2 instance `i-07a45e64195948f2f` (named "myec2") was using the `EC2-ADMIN` role which had the `AdministratorAccess` policy attached. This policy grants full access to all AWS services and resources, violating the principle of least privilege.

## Remediation Steps Taken

1. **Created a new limited IAM policy**:
   ```bash
   aws iam create-policy --policy-name EC2-Limited-Policy --policy-document file://ec2-limited-policy.json
   ```

2. **Created a new IAM role with proper trust relationship**:
   ```bash
   aws iam create-role --role-name EC2-Limited-Role --assume-role-policy-document file://ec2-limited-trust-policy.json
   ```

3. **Attached appropriate policies to the new role**:
   ```bash
   aws iam attach-role-policy --role-name EC2-Limited-Role --policy-arn arn:aws:iam::384612698411:policy/EC2-Limited-Policy
   aws iam attach-role-policy --role-name EC2-Limited-Role --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
   aws iam attach-role-policy --role-name EC2-Limited-Role --policy-arn arn:aws:iam::aws:policy/AmazonSSMPatchAssociation
   ```

4. **Created a new instance profile**:
   ```bash
   aws iam create-instance-profile --instance-profile-name EC2-Limited-Profile
   aws iam add-role-to-instance-profile --role-name EC2-Limited-Role --instance-profile-name EC2-Limited-Profile
   ```

5. **Removed the old instance profile from the EC2 instance**:
   ```bash
   aws ec2 disassociate-iam-instance-profile --association-id iip-assoc-04714c7dd0b0feb7a
   ```

6. **Attached the new instance profile to the EC2 instance**:
   ```bash
   aws ec2 associate-iam-instance-profile --instance-id i-07a45e64195948f2f --iam-instance-profile Name=EC2-Limited-Profile
   ```

## Verification

The EC2 instance now has the limited-permission role attached:
```bash
aws ec2 describe-iam-instance-profile-associations --filters Name=instance-id,Values=i-07a45e64195948f2f
```

## Next Steps

1. **Monitor for permission errors**: Watch CloudTrail and CloudWatch Logs for any permission errors that might indicate missing permissions
2. **Customize S3 bucket permissions**: Update the policy with specific S3 bucket names if needed
3. **Consider removing the old role**: If no other resources are using the EC2-ADMIN role, consider removing it
4. **Document the change**: Update internal documentation to reflect this security improvement

## Security Improvement

This change significantly improves the security posture by:
- Reducing the attack surface if the instance is compromised
- Following the principle of least privilege
- Providing only the permissions necessary for the instance to function
- Eliminating the risk of accidental or malicious changes to critical AWS resources
