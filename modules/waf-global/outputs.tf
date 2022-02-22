output web_acl_id {
  description = "AWS WAF web acl id."
  value       = aws_waf_web_acl.waf_acl.id
}

output web_acl_name {
  description = "The name or description of the web ACL."
  value       = aws_waf_web_acl.waf_acl.name
}

output web_acl_metric_name {
  description = "The name or description for the Amazon CloudWatch metric of this web ACL."
  value       = aws_waf_web_acl.waf_acl.metric_name
}

output rule_group_id {
  description = "AWS WAF rule group id."
  value       = aws_waf_rule_group.blacklist.id
}

output rule_group_arn {
  description = "The ARN of the WAF rule group."
  value       = aws_waf_rule_group.blacklist.arn
}