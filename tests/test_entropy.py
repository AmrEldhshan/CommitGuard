from __future__ import annotations

import unittest

from core.entropy import shannon_entropy


class EntropyTests(unittest.TestCase):
    def test_empty_and_repeated(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaaaaaa"), 0.0)

    def test_two_symbols(self):
        self.assertAlmostEqual(shannon_entropy("abab"), 1.0)

    def test_high_entropy_secret(self):
        self.assertGreater(shannon_entropy("aB3xQ9zL0mN2pR7"), 3.5)


if __name__ == "__main__":
    unittest.main()
