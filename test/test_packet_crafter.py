import unittest
import PacketCrafter.packet_crafter as pc


class PacketCrafterTest(unittest.TestCase):
    def test_convert_ip_address(self):
        self.assertEqual(pc.convert_ip_address('192.168.0.1'), 'c0a8 0001')
        self.assertIsNone(pc.convert_ip_address('192.168.0.1.1'))


if __name__ == '__main__':
    unittest.main()
