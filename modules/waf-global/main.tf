#
# This is our WAF ACL with each rule defined and prioritized accordingly.
#
resource aws_waf_web_acl waf_acl {
  depends_on = [
    aws_waf_rule.whitelist,
    aws_waf_rule_group.blacklist,
  ]
  name        = "${var.waf_prefix}-generic-owasp-acl"
  metric_name = replace("${var.waf_prefix}genericowaspacl", "/[^0-9A-Za-z]/", "")

  default_action {
    type = "ALLOW"
  }

  # Whitelist rule sets
  rules {
    action {
      type = var.rule_whitelist_type
    }

    priority = 10
    rule_id  = aws_waf_rule.whitelist.id
    type     = "REGULAR"
  }

  rules {
    action {
      type = var.rule_group_blacklist_type
    }
    override_action {
      type   = "COUNT"
    }

    priority = 20
    rule_id  = aws_waf_rule_group.blacklist.id //todo
    type     = "GROUP"
  }
    

/*
  #
  # Note: we are using this but we are not applying body size restrictions because
  #  uploads could be affected by that.
  #
  rules {
    action {
      type = var.rule_size_restriction_action_type
    }

    priority = 1
    rule_id  = aws_waf_rule.restrict_sizes.id
    type     = "REGULAR"
  }

  #
  # Reason: we are not implementing an IP blacklist yet.
  # So COMMENT rule block below to deactivate this rule
  #
  rules {
    action {
      type = var.rule_blacklisted_ips_action_type
    }

    priority = 2
    rule_id  = aws_waf_rule.detect_blacklisted_ips.id
    type     = "REGULAR"
  }

  #
  # Reason: the apps do not use auth tokens yet.
  # So COMMENT rule block below to deactivate this rule
  #
  rules {
    action {
      type = var.rule_auth_tokens_action
    }

    priority = 3
    rule_id  = aws_waf_rule.detect_bad_auth_tokens.id
    type     = "REGULAR"
  }

  rules {
    action {
      type = var.rule_sqli_action
    }

    priority = 4
    rule_id  = aws_waf_rule.mitigate_sqli.id
    type     = "REGULAR"
  }
  rules {
    action {
      type = var.rule_xss_action
    }

    priority = 5
    rule_id  = aws_waf_rule.mitigate_xss.id
    type     = "REGULAR"
  }
  rules {
    action {
      type = var.rule_lfi_rfi_action
    }

    priority = 6
    rule_id  = aws_waf_rule.detect_rfi_lfi_traversal.id
    type     = "REGULAR"
  }

  #
  # Reason: we don't have PHP stacks on this project.
  # So COMMENT rule block below to deactivate this rule
  #
  rules {
    action {
      type = var.rule_php_insecurities_action_type
    }

    priority = 7
    rule_id  = aws_waf_rule.detect_php_insecure.id
    type     = "REGULAR"
  }

  #
  # Reason: the apps do not use CSRF tokens.
  # So COMMENT rule block below to deactivate this rule
  #
  rules {
    action {
      type = var.rule_csrf_action_type
    }

    priority = 8
    rule_id  = aws_waf_rule.enforce_csrf.id
    type     = "REGULAR"
  }

  #
  # Reason: this should cover any config files in our web root folder.
  #
  rules {
    action {
      type = var.rule_ssi_action_type
    }

    priority = 9
    rule_id  = aws_waf_rule.detect_ssi.id
    type     = "REGULAR"
  }

  #
  # Reason: we do not have IP restriction on admin sections.
  # So COMMENT rule block below to deactivate this rule
  #
  rules {
    action {
      type = var.rule_admin_access_action_type
    }

    priority = 10
    rule_id  = aws_waf_rule.detect_admin_access.id
    type     = "REGULAR"
  }
*/

  tags = var.tags
}

## Rulegroup Blacklist

resource aws_waf_rule_group blacklist {
  depends_on  = [  
    aws_waf_rule.restrict_sizes,
    aws_waf_rule.detect_blacklisted_ips,
    aws_waf_rule.detect_bad_auth_tokens,
    aws_waf_rule.mitigate_sqli,
    aws_waf_rule.mitigate_xss,
    aws_waf_rule.detect_rfi_lfi_traversal,
    aws_waf_rule.detect_php_insecure,
    aws_waf_rule.enforce_csrf,
    aws_waf_rule.detect_ssi,
    aws_waf_rule.detect_admin_access,
  ]
  name        = "${var.waf_prefix}-rulegroup-blacklist"
  metric_name = replace("${var.waf_prefix}rulegroupblacklist", "/[^0-9A-Za-z]/", "")

  activated_rule {
    action {
      type = var.rule_size_restriction_action_type
    }

    priority = 10
    rule_id  = aws_waf_rule.restrict_sizes.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_blacklisted_ips_action_type
    }

    priority = 20
    rule_id  = aws_waf_rule.detect_blacklisted_ips.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_auth_tokens_action
    }

    priority = 30
    rule_id  = aws_waf_rule.detect_bad_auth_tokens.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_sqli_action
    }

    priority = 40
    rule_id  = aws_waf_rule.mitigate_sqli.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_xss_action
    }

    priority = 50
    rule_id  = aws_waf_rule.mitigate_xss.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_lfi_rfi_action
    }

    priority = 60
    rule_id  = aws_waf_rule.detect_rfi_lfi_traversal.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_php_insecurities_action_type
    }

    priority = 70
    rule_id  = aws_waf_rule.detect_php_insecure.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_csrf_action_type
    }

    priority = 80
    rule_id  = aws_waf_rule.enforce_csrf.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_ssi_action_type
    }

    priority = 90
    rule_id  = aws_waf_rule.detect_ssi.id
    type     = "REGULAR"
  }

  activated_rule {
    action {
      type = var.rule_admin_access_action_type
    }

    priority = 100
    rule_id  = aws_waf_rule.detect_admin_access.id
    type     = "REGULAR"
  }
}
