from itertools import product
from copy import deepcopy


class FilterModule(object):
    def filters(self):
        return {
            'asSecGroupRules': self.filter_as_sec_group_rules,
            'flagOptions': self.filter_flagOptions,
            'subnetsConfigToDict': self.filter_subnetsConfigToDict,
            'appendProperty': self.filter_appendProperty
        }

    # -----------------------------------------------------------
    # --------- asSecGroupRules ---------------------------------
    # -----------------------------------------------------------
    def filter_as_sec_group_rules(self, rules_data):
        return [
            {
                'cidr_ip': rule['ip'],
                'proto': rule['proto'],
                'from_port': self.port_range_start(rule['port_range']),
                'to_port': self.port_range_end(rule['port_range']),
                'rule_desc': rule['description']
            } for rule in rules_data
        ]

    def port_range_start(self, port_range: str) -> int:
        if port_range.lower() == 'all':
            port = 0
        else:
            hyphen_position = port_range.find('-')
            port_str = port_range[0:hyphen_position]\
                if hyphen_position > -1\
                else port_range
            port = int(port_str)
        return port

    def port_range_end(self, port_range: str) -> int:
        if port_range.lower() == 'all':
            port = 65535
        else:
            port = int(port_range[port_range.find('-') + 1:])
        return port

    # -----------------------------------------------------------
    # --------- flagOptions -------------------------------------
    # -----------------------------------------------------------
    def filter_flagOptions(self, options, option_flag):
        '''
            Used for a CLI options list where a single option-flag
            is used multiple times on different arguments
        '''
        return [
            item for pair in [
                [option_flag, val]
                for val in options
            ]
            for item in pair
        ]

    # -----------------------------------------------------------
    # --------- subnetsConfigToDict -----------------------------
    # -----------------------------------------------------------
    def filter_subnetsConfigToDict(self, subnetsConfig):
        return [
            {'ordinal': ordinal,
                'cidr': item['cidr'], 'topics': item['topics']}
            for sn in subnetsConfig
            for (ordinal, item) in product(range(sn['instances']), [sn])
        ]

    # -----------------------------------------------------------
    # --------- appendProperty ----------------------------------
    # -----------------------------------------------------------
    def filter_appendProperty(self, data, prop, appendage):
        data_copy = deepcopy(data)
        data_copy[prop] = data_copy[prop] + appendage
        return data_copy
