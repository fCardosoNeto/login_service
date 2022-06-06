import unittest
from ..model.validation import validate_params
from unittest import TestCase

class AppTest(TestCase):
  def test_validate_params(self):
    valid_user = {'login': 'teste', 'password': 'teste'}
    invalid_user = {'login': 'errado'}
    self.assertTrue(validate_params(valid_user))
    self.assertFalse(validate_params(invalid_user))

if __name__ == '__main__':
  unittest.main()