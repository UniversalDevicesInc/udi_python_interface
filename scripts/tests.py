import unittest
import udi_interface

class TestPoly(unittest.TestCase):

    def test_poly(self):
        polyglot = udi_interface.Interface('Test')
        print(polyglot.network_interface)
        #polyglot.assertIsInstance(polyglot, polyinterface.Interface)


if __name__ == "__main__":
    unittest.main()
