import unittest
import fingerprinter.packetcrafter.calculate_header_checksum as calc_check


class CalculateHeaderChecksumTestCase(unittest.TestCase):
    def test_ones_complement(self):
        self.assertEqual(calc_check.ones_complement_addition(5, 6), 11)
        self.assertEqual(calc_check.ones_complement_addition(13, 6), 19)
        self.assertEqual(calc_check.ones_complement_addition(int("0x8000", 16), int("0xc001", 16)), int("0x4002", 16))

    def test_ip(self):
        self.assertEqual(calc_check.ip("4500 00cd 29e7 4000 8006 0000 c0a8 009e c0a8 000c"), "0x4e49")


if __name__ == '__main__':
    unittest.main()
