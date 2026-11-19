"""CIDR 与时间基础规则测试：同族匹配、IPv6 等价拼写、半开区间。"""

import unittest

from mirror_auth.cidr import (
    address_in_network,
    canonical_address,
    parse_address,
    parse_network,
)
from mirror_auth.timeutil import format_time, parse_time


class CidrTest(unittest.TestCase):

    def test_ipv4_in_network_and_boundary(self):
        net = parse_network("192.0.2.0/24")
        self.assertTrue(address_in_network(parse_address("192.0.2.1"), net))
        self.assertTrue(address_in_network(parse_address("192.0.2.255"), net))
        self.assertFalse(address_in_network(parse_address("192.0.3.1"), net))

    def test_strict_network_rejects_host_bits(self):
        with self.assertRaises(ValueError):
            parse_network("192.0.2.5/24")

    def test_cross_family_never_matches(self):
        v6_addr = parse_address("2001:db8::1")
        v4_net = parse_network("192.0.2.0/24")
        self.assertFalse(address_in_network(v6_addr, v4_net))
        v4_addr = parse_address("192.0.2.1")
        v6_net = parse_network("2001:db8::/32")
        self.assertFalse(address_in_network(v4_addr, v6_net))

    def test_ipv6_equivalent_spelling(self):
        full = parse_address("2001:0db8:0000:0000:0000:0000:0000:000a")
        compact = parse_address("2001:db8::a")
        self.assertEqual(canonical_address(full), canonical_address(compact))
        net = parse_network("2001:db8::/32")
        self.assertTrue(address_in_network(full, net))
        self.assertTrue(address_in_network(compact, net))

    def test_narrow_prefix_inside_wide(self):
        wide = parse_network("192.0.2.0/24")
        narrow = parse_network("192.0.2.48/30")  # .48 -.51
        addr = parse_address("192.0.2.50")
        self.assertTrue(address_in_network(addr, wide))
        self.assertTrue(address_in_network(addr, narrow))
        self.assertFalse(address_in_network(parse_address("192.0.2.47"), narrow))


class TimeTest(unittest.TestCase):

    def test_half_open_window_semantics(self):
        start = parse_time("2026-11-20T00:00:00Z")
        end = parse_time("2026-11-21T00:00:00Z")
        self.assertTrue(start <= parse_time("2026-11-20T00:00:00Z") < end)
        self.assertFalse(start <= end < end)          # 终点不含
        self.assertTrue(start <= parse_time(
            "2026-11-20T23:59:59.999999Z") < end)

    def test_naive_datetime_rejected(self):
        with self.assertRaises(ValueError):
            parse_time("2026-11-20T00:00:00")

    def test_offset_normalized_to_utc(self):
        self.assertEqual(
            parse_time("2026-11-20T08:00:00+08:00"),
            parse_time("2026-11-20T00:00:00Z"),
        )

    def test_roundtrip(self):
        text = "2026-11-20T10:00:00Z"
        self.assertEqual(format_time(parse_time(text)), text)


if __name__ == "__main__":
    unittest.main()
