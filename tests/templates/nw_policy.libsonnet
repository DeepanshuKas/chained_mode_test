{
  emptyOrObject(key, string)::
    function(value)
      if value == '' then
        {}
      else
        {[key]: string % value},

  addPodSelector(selector)::
    if selector == '' then
        {'podSelector': {}}
    else
        /*
        local attr = std.split(selector, "=");
        {'podSelector':
            {'matchLabels':
               {[attr[0]]: attr[1]}
            }
        },*/
        {
            'podSelector': std.parseJson(selector)
        },

  addIngressRules(ingress_rules)::
    if ingress_rules == '' then
        {}
    else
        {
            'ingress': std.parseJson(ingress_rules)
        },

  addEgressRules(egress_rules)::
    if egress_rules == '' then
        {}
    else
        {
            'egress': std.parseJson(egress_rules)
        },

  /* This function takes as an argument either the empty string or an
   array of two strings.
   */
  annotateEpg:: self.emptyOrObject('opflex.cisco.com/endpoint-group',
      std.toString(
      {'tenant': '%s',
      'app-profile': 'kubernetes',
      'name': '%s'})),
}
