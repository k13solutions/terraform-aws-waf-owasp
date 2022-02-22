## 0.
## Whitelisting exceptions

resource aws_waf_rule whitelist {
  depends_on = [
    aws_waf_ipset.whitelisted_ips,
    aws_waf_ipset.whitelisted_elastic_ips,
    aws_waf_byte_match_set.whitelisted_user_agent_match_set,
  ]
  name        = "${var.waf_prefix}-whitelist"
  metric_name = replace("${var.waf_prefix}whitelist", "/[^0-9A-Za-z]/", "")

  predicates {
    data_id = aws_waf_ipset.whitelisted_ips.id
    negated = false
    type    = "IPMatch"
  }

  predicates {
    data_id = aws_waf_ipset.whitelisted_elastic_ips.id
    negated = false
    type    = "IPMatch"
  }

  predicates {
    data_id = aws_waf_byte_match_set.whitelisted_user_agent_match_set.id
    negated = false
    type    = "ByteMatch"
  }
}

# Whitelisted IPs
resource aws_waf_ipset whitelisted_ips {
  name = "${var.waf_prefix}-generic-match-whitelisted-ips"
  dynamic ip_set_descriptors {
    for_each = var.whitelisted_ips

    content {
      type  = "IPV4"
      value = ip_set_descriptors.value
    }
  }
}

# Different ElasticIPs used by VPN
resource aws_waf_ipset whitelisted_elastic_ips {
  name = "${var.waf_prefix}-generic-match-whitelisted_elastic_ips"
  dynamic ip_set_descriptors {
    for_each = var.whitelisted_elastic_ips

    content {
      type  = "IPV4"
      value = ip_set_descriptors.value
    }
  }
}

# Whitelisted User Agent
resource aws_waf_byte_match_set whitelisted_user_agent_match_set {
  name = "${var.waf_prefix}-generic-whitelisted-user-agent-header"

/*
  dynamic user_agent_descriptor {
      for_each = var.whitelisted_user_agent_header

      content {
          byte_match_tuples {
                text_transformation   = "NONE"
                target_string         = user_agent_descriptor.value
                positional_constraint = "CONTAINS"

                field_to_match {
                type = "HEADER"
                data = "user-agent"
                }
            }
      }
  }
*/

  byte_match_tuples {
    text_transformation   = "NONE"
    target_string         = var.whitelisted_user_agent_header
    positional_constraint = "CONTAINS"

    field_to_match {
      type = "HEADER"
      data = "user-agent"
    }
  }

}
