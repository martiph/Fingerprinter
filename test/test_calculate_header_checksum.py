import unittest
import calculate_header_checksum as calc_check


class CalculateHeaderChecksumTestCase(unittest.TestCase):
    def test_ones_complement(self):
        self.assertEqual(calc_check.ones_complement_addition(5, 6), 11)
        self.assertEqual(calc_check.ones_complement_addition(13, 6), 8)


if __name__ == '__main__':
    unittest.main()
